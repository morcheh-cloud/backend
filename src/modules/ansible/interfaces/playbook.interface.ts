export type IPlaybook = {
	doc: {
		notes: Array<string>
		author: Array<string>
		module: string
		options: {
			region: {
				type: string
				aliases: Array<string>
				description: Array<string>
			}
			profile: {
				type: string
				aliases: Array<string>
				description: Array<string>
			}
			all_facts: {
				type: string
				default: boolean
				description: Array<string>
			}
			access_key: {
				type: string
				aliases: Array<string>
				description: Array<string>
			}
			aws_config: {
				type: string
				description: Array<string>
			}
			secret_key: {
				type: string
				aliases: Array<string>
				description: Array<string>
			}
			stack_name: {
				type: string
				description: Array<string>
			}
			endpoint_url: {
				type: string
				aliases: Array<string>
				description: Array<string>
			}
			stack_events: {
				type: string
				default: boolean
				description: Array<string>
			}
			stack_policy: {
				type: string
				default: boolean
				description: Array<string>
			}
			aws_ca_bundle: {
				type: string
				description: Array<string>
			}
			session_token: {
				type: string
				aliases: Array<string>
				description: Array<string>
			}
			stack_template: {
				type: string
				default: boolean
				description: Array<string>
			}
			validate_certs: {
				type: string
				default: boolean
				description: Array<string>
			}
			stack_resources: {
				type: string
				default: boolean
				description: Array<string>
			}
			stack_change_sets: {
				type: string
				default: boolean
				description: Array<string>
			}
			debug_botocore_endpoint_logs: {
				type: string
				default: boolean
				description: Array<string>
			}
		}
		filename: string
		collection: string
		has_action: boolean
		description: Array<string>
		requirements: Array<string>
		version_added: string
		short_description: string
		version_added_collection: string
	}
	return: {
		cloudformation: {
			type: string
			contains: {
				stack_tags: {
					type: string
					sample: {
						TagOne: string
						TagTwo: string
					}
					returned: string
					description: string
				}
				stack_events: {
					type: string
					returned: string
					description: string
				}
				stack_policy: {
					type: string
					returned: string
					description: string
				}
				stack_outputs: {
					type: string
					sample: {
						ApplicationDatabaseName: string
					}
					returned: string
					description: string
				}
				stack_template: {
					type: string
					returned: string
					description: string
				}
				stack_resources: {
					type: string
					sample: {
						AutoScalingGroup: string
						ApplicationDatabase: string
						AutoScalingSecurityGroup: string
					}
					returned: string
					description: string
				}
				stack_parameters: {
					type: string
					sample: {
						DatabaseEngine: string
						DatabasePassword: string
					}
					returned: string
					description: string
				}
				stack_change_sets: {
					type: string
					returned: string
					description: string
				}
				stack_description: {
					type: string
					contains: {
						tags: {
							type: string
							contains: {
								key: {
									type: string
									returned: string
									description: string
								}
								value: {
									type: string
									returned: string
									description: string
								}
							}
							elements: string
							returned: string
							description: string
						}
						outputs: {
							type: string
							contains: {
								output_key: {
									type: string
									returned: string
									description: string
								}
								output_value: {
									type: string
									returned: string
									description: string
								}
							}
							elements: string
							returned: string
							description: string
						}
						stack_id: {
							type: string
							returned: string
							description: string
						}
						parameters: {
							type: string
							contains: {
								parameter_key: {
									type: string
									returned: string
									description: string
								}
								parameter_value: {
									type: string
									returned: string
									description: string
								}
							}
							elements: string
							returned: string
							description: string
						}
						stack_name: {
							type: string
							returned: string
							description: string
						}
						description: {
							type: string
							returned: string
							description: string
						}
						capabilities: {
							type: string
							elements: string
							returned: string
							description: string
						}
						stack_status: {
							type: string
							returned: string
							description: string
						}
						creation_time: {
							type: string
							returned: string
							description: string
						}
						deletion_time: {
							type: string
							returned: string
							description: string
						}
						disable_rollback: {
							type: string
							returned: string
							description: string
						}
						drift_information: {
							type: string
							contains: {
								stack_drift_status: {
									type: string
									returned: string
									description: string
								}
								last_check_timestamp: {
									type: string
									returned: string
									description: string
								}
							}
							returned: string
							description: string
						}
						notification_arns: {
							type: string
							elements: string
							returned: string
							description: string
						}
						rollback_configuration: {
							type: string
							contains: {
								rollback_triggers: {
									type: string
									contains: {
										arn: {
											type: string
											returned: string
											description: string
										}
										type: {
											type: string
											returned: string
											description: string
										}
									}
									elements: string
									returned: string
									description: string
								}
							}
							returned: string
							description: string
						}
						enable_termination_protection: {
							type: string
							returned: string
							description: string
						}
					}
					returned: string
					description: string
				}
				stack_resource_list: {
					type: string
					returned: string
					description: string
				}
			}
			returned: string
			description: Array<string>
		}
	}
	examples: string
	metadata: unknown
}
