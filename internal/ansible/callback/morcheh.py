# Morcheh's Ansible callback: writes one JSON object per line to the file
# descriptor in MORCHEH_EVENTS_FD, so Morcheh can show plays, tasks and each
# host's result without parsing the human output (which still goes to stdout
# through the default callback).
#
# Results arrive here already censored for no_log tasks.

from __future__ import annotations

DOCUMENTATION = """
    name: morcheh
    type: notification
    short_description: Structured events for Morcheh
    description: Writes plays, tasks and host results as JSON lines.
"""

import json
import os
import time

from ansible.plugins.callback import CallbackBase

STR_CAP = 6000
LIST_CAP = 60
DEPTH_CAP = 8
# Keys every module result carries that say nothing to a person.
NOISE = {"_ansible_no_log", "_ansible_verbose_always", "_ansible_verbose_override",
         "_ansible_item_label", "_ansible_ignore_errors", "_ansible_parsed",
         "_ansible_delegated_vars", "_ansible_item_result", "ansible_loop_var",
         "_ansible_no_log_values", "warnings_filter"}

# Keys shown on their own, left out of "data".
SHOWN = {"msg", "rc", "stdout", "stderr", "stdout_lines", "stderr_lines", "diff",
         "results", "changed", "failed", "skipped", "unreachable"}


def trim(v, depth=0):
    if depth > DEPTH_CAP:
        return "…"
    if isinstance(v, str):
        v = v.replace("\x00", "")  # PostgreSQL refuses it
        return v if len(v) <= STR_CAP else v[:STR_CAP] + "\n… (cut by Morcheh)"
    if isinstance(v, (bool, int, float)) or v is None:
        return v
    if isinstance(v, dict):
        return {str(k): trim(x, depth + 1) for k, x in v.items() if k not in NOISE}
    if isinstance(v, (list, tuple, set)):
        items = [trim(x, depth + 1) for x in list(v)[:LIST_CAP]]
        if len(v) > LIST_CAP:
            items.append("… %d more" % (len(v) - LIST_CAP))
        return items
    return trim(str(v), depth)


def parts(result):
    # ansible-core 2.19+ hands a CallbackTaskResult; older versions a TaskResult.
    host = getattr(result, "host", None) or result._host
    task = getattr(result, "task", None) or result._task
    data = getattr(result, "result", None)
    if not isinstance(data, dict):
        data = result._result
    return host, task, data


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "notification"
    CALLBACK_NAME = "morcheh"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        fd = os.environ.get("MORCHEH_EVENTS_FD")
        self._out = os.fdopen(int(fd), "w", buffering=1, encoding="utf-8", errors="replace") if fd else None
        self._play = None

    def _emit(self, event, **fields):
        if self._out is None:
            return
        fields["e"] = event
        fields["t"] = time.time()
        try:
            self._out.write(json.dumps(fields, default=str, ensure_ascii=False) + "\n")
        except Exception:  # Morcheh went away; the run goes on regardless.
            self._out = None

    # ---- Plays and tasks ----

    def v2_playbook_on_play_start(self, play):
        self._play = str(play._uuid)
        self._emit("play", id=self._play, name=play.get_name().strip(),
                   hosts=", ".join(play.hosts) if isinstance(play.hosts, list) else str(play.hosts))

    def _task(self, task, handler):
        self._emit("task", id=str(task._uuid), play=self._play, name=task.get_name().strip(),
                   action=task.action, handler=handler, path=task.get_path() or "")

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._task(task, False)

    def v2_playbook_on_handler_task_start(self, task):
        self._task(task, True)

    def v2_playbook_on_no_hosts_matched(self):
        self._emit("no_hosts", play=self._play, reason="matched")

    def v2_playbook_on_no_hosts_remaining(self):
        self._emit("no_hosts", play=self._play, reason="remaining")

    def v2_runner_on_start(self, host, task):
        self._emit("start", task=str(task._uuid), host=host.get_name())

    # ---- Results ----

    def _result(self, result, status):
        host, task, data = parts(result)
        data = dict(data)
        items = None
        if isinstance(data.get("results"), list):
            items = []
            for r in data.pop("results")[:LIST_CAP]:
                if not isinstance(r, dict):
                    continue
                s = "failed" if r.get("failed") else "skipped" if r.get("skipped") else \
                    "changed" if r.get("changed") else "ok"
                label = r.get("_ansible_item_label", r.get("item"))
                items.append({"item": trim(label), "status": s, "msg": trim(r.get("msg", "")),
                              "rc": r.get("rc"), "stdout": trim(r.get("stdout", "")),
                              "stderr": trim(r.get("stderr", ""))})
        if status == "ok" and data.get("changed"):
            status = "changed"
        self._emit("result", task=str(task._uuid), host=host.get_name(), status=status,
                   msg=trim(data.get("msg", "")) if not isinstance(data.get("msg"), (dict, list)) else trim(json.dumps(data.get("msg"), default=str)),
                   rc=data.get("rc"), stdout=trim(data.get("stdout", "")), stderr=trim(data.get("stderr", "")),
                   diff=trim(data.get("diff")) if data.get("diff") else None,
                   items=items, data=trim({k: v for k, v in data.items() if k not in SHOWN}))

    def v2_runner_on_ok(self, result):
        self._result(result, "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._result(result, "ignored" if ignore_errors else "failed")

    def v2_runner_on_skipped(self, result):
        self._result(result, "skipped")

    def v2_runner_on_unreachable(self, result):
        self._result(result, "unreachable")

    def v2_runner_retry(self, result):
        host, task, data = parts(result)
        self._emit("retry", task=str(task._uuid), host=host.get_name(),
                   attempt=data.get("attempts"), retries=data.get("retries"))

    # ---- The end ----

    def v2_playbook_on_stats(self, stats):
        hosts = {}
        for h in sorted(stats.processed.keys()):
            s = stats.summarize(h)
            hosts[h] = {"ok": s.get("ok", 0), "changed": s.get("changed", 0),
                        "failed": s.get("failures", 0), "unreachable": s.get("unreachable", 0),
                        "skipped": s.get("skipped", 0), "rescued": s.get("rescued", 0),
                        "ignored": s.get("ignored", 0)}
        self._emit("stats", stats=hosts)
