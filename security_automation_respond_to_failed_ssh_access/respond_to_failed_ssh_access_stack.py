import fileinput
import json
from datetime import datetime

from aws_cdk import aws_cloudwatch as _cloudwatch
from aws_cdk import aws_cloudwatch_actions as _cloudwatch_actions
from aws_cdk import aws_ec2 as _ec2
from aws_cdk import aws_iam as _iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_logs as _logs
from aws_cdk import aws_logs_destinations as _logs_destination
from aws_cdk import aws_sns as _sns
from aws_cdk import aws_sns_subscriptions as _subs
from aws_cdk import aws_stepfunctions as _sfn
from aws_cdk import aws_stepfunctions_tasks as _tasks
from aws_cdk import core


class global_args:
    '''
    Helper to define global statics
    '''
    OWNER                       = "MystiqueInfoSecurity"
    ENVIRONMENT                 = "production"
    SOURCE_INFO                 = "https://github.com/miztiik/security-automation-respond-to-failed-ssh-access"
    INFO_SEC_OPS_EMAIL          = "INFOSECOPS@EMAIL.COM"

class RespondToFailedSshAccessStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Lets create couple of instances to test
        vpc = _ec2.Vpc(
                self, "abacVPC",
                cidr="10.13.0.0/21",
                max_azs=2,
                nat_gateways=0,
                subnet_configuration=[
                    _ec2.SubnetConfiguration(name="pubSubnet", cidr_mask=24, subnet_type=_ec2.SubnetType.PUBLIC)
                ]
            )
        core.Tag.add(vpc,key="ServiceProvider",value="KonStone",include_resource_types=[])

        weak_sg = _ec2.SecurityGroup(self,
            "web_sec_grp",
            vpc = vpc,
            description="Allow internet access from the world",
            allow_all_outbound = True
            )
        weak_sg.add_ingress_rule(_ec2.Peer.any_ipv4(), 
            _ec2.Port.tcp(22),
            "Allow internet access from the world."
            )

        # We are using the latest AMAZON LINUX AMI
        # Benefit of having SSM Agent pre-installed
        ami_id = _ec2.AmazonLinuxImage(generation = _ec2.AmazonLinuxGeneration.AMAZON_LINUX_2).get_image(self).image_id

        # https://docs.aws.amazon.com/cdk/api/latest/python/aws_cdk.aws_iam/Role.html
        instace_profile_role = _iam.Role(
            self,
            'ec2ssmroleid',
            assumed_by=_iam.ServicePrincipal('ec2.amazonaws.com'),
            role_name="instace_profile_role"
            )

        instace_profile_role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name('AmazonSSMManagedInstanceCore')
            )

        instance_profile_role_additional_perms=_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            resources=[
                "arn:aws:logs:*:*:*",
                ],
            actions=[
                "logs:Create*",
                "logs:PutLogEvents"
                ]
            )
        instance_profile_role_additional_perms.sid="PutBucketPolicy"
        instace_profile_role.add_to_policy( instance_profile_role_additional_perms )

        inst_profile_01 = _iam.CfnInstanceProfile(
            self,
            "instProfile01Id",
                roles=[instace_profile_role.role_name],
            )

        # Let us bootstrap the server with the required agents
        try:
            with open("./bootstrap_scripts/install_agents.sh", mode = 'rb') as file:
                bootstrap_data = file.read()
        except OSError:
            print('Failed to get UserData script')

        install_agents = _ec2.UserData.for_linux()
        install_agents.add_commands(str(bootstrap_data, 'utf-8'))


        # The EC2 Instance to monitor for failed SSH Logins
        ssh_monitored_inst_01 = _ec2.CfnInstance(self,
            "sshMonitoredInstance01",
            image_id = ami_id,
            instance_type = "t2.micro",
            monitoring = False,
            tags = [
                { "key": "ServiceProvider", "value": "KonStone" }
            ],
            iam_instance_profile = inst_profile_01.ref,
            network_interfaces = [{
                "deviceIndex": "0",
                "associatePublicIpAddress": True,
                "subnetId": vpc.public_subnets[0].subnet_id,
                "groupSet": [weak_sg.security_group_id]
            }], #https: //github.com/aws/aws-cdk/issues/3419
            user_data = core.Fn.base64(install_agents.render()),
            )

        """
        linux_ami = _ec2.GenericLinuxImage({ "cn-northwest-1": "ami-0f62e91915e16cfc2","eu-west-1": "ami-12345678"})
        ssh_monitored_inst_01_02 = _ec2.Instance(self,
            "monitoredInstance02",
            instance_type=_ec2.InstanceType(instance_type_identifier="t2.micro"),
            instance_name="monitoredInstance02",
            machine_image=linux_ami,
            vpc=vpc,
            security_group=[weak_sg.security_group_id],
            # vpc_subnets=_ec2.SubnetSelection(subnet_type=_ec2.SubnetType.PUBLIC)
            vpc_subnets=vpc.public_subnets[0].subnet_id,
            # user_data=_ec2.UserData.custom(t_user_data)
            )
        """

        # The log group name to store logs
        info_sec_ops_log_group = _logs.LogGroup(self, "infoSecOpsLogGroupId",
            log_group_name=(
                f"/Mystique/InfoSec/Automation/"
                f"{ssh_monitored_inst_01.ref}"
            ),
            retention=_logs.RetentionDays.ONE_WEEK
        )


        # Defines an AWS Lambda resource

        with open("lambda_src/quarantine_ec2_instance.py", encoding="utf8") as fp:
            quarantine_ec2_instance_fn_handler_code = fp.read()

        quarantine_ec2_instance_fn = _lambda.Function(
            self,
            id='quarantineEc2InstanceFnId',
            function_name="quarantine_ec2_instance",
            runtime=_lambda.Runtime.PYTHON_3_7,
            code=_lambda.InlineCode(quarantine_ec2_instance_fn_handler_code),
            handler='index.lambda_handler',
            timeout=core.Duration.seconds(5)
        )
        quarantine_ec2_instance_fn_perms=_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            resources=[
                "*",
                ],
            actions=[
                "ec2:RevokeSecurityGroupIngress",
                "ec2:DescribeSecurityGroupReferences",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:ApplySecurityGroupsToClientVpnTargetNetwork",
                "ec2:DescribeSecurityGroups",
                "ec2:CreateSecurityGroup",
                "ec2:DescribeInstances",
                "ec2:CreateTags",
                "ec2:StopInstances",
                "ec2:CreateVolume",
                "ec2:CreateSnapshots",
                "ec2:CreateSnapshot",
                "ec2:DescribeSnapshots",
                "ec2:ModifyInstanceAttribute"
            ]
        )
        quarantine_ec2_instance_fn_perms.sid="AllowLambdaToQurantineEC2"
        quarantine_ec2_instance_fn.add_to_role_policy( quarantine_ec2_instance_fn_perms )

        info_sec_ops_topic = _sns.Topic(self, "infoSecOpsTopicId",
            display_name="InfoSecTopic",
            topic_name="InfoSecOpsTopic"
        )


        # Ref: https://docs.aws.amazon.com/cdk/api/latest/docs/aws-stepfunctions-readme.html
        ###############################################################################
        ################# STEP FUNCTIONS EXPERIMENTAL CODE - UNSTABLE #################
        ###############################################################################
 
        quarantine_ec2_instance_task = _sfn.Task(self, "Qurantine EC2 Instance",
            task=_tasks.InvokeFunction(quarantine_ec2_instance_fn),
            result_path="$"
        )

        notify_secops_task = _sfn.Task(self, "Notify InfoSecOps",
            task=_tasks.PublishToTopic(info_sec_ops_topic,
                integration_pattern=_sfn.ServiceIntegrationPattern.FIRE_AND_FORGET,
                message=_sfn.TaskInput.from_data_at("$.message"),
                subject="SSH Error Response Notification"
                )
        )

        ssh_error_response_failure = _sfn.Fail(self, "SSH Error Response Actions Failed",
            cause="All Response Actions were NOT completed",
            error="Check Logs"
        )

        ssh_error_response_success = _sfn.Succeed(self, "SSH Error Response Actions Succeeded",
            comment="All Response Action Completed Successfully",
        )

        ssh_error_response_sfn_definition = quarantine_ec2_instance_task\
            .next(notify_secops_task\
                .next(_sfn.Choice(self, "SSH Errors Response Complete?")\
                    .when(_sfn.Condition.number_equals("$.SdkHttpMetadata.HttpStatusCode", 200),ssh_error_response_success)\
                    .when(_sfn.Condition.not_(
                        _sfn.Condition.number_equals("$.SdkHttpMetadata.HttpStatusCode", 200)), ssh_error_response_failure)\
                    .otherwise(ssh_error_response_failure)
                    )
            )

        ssh_error_response_statemachine = _sfn.StateMachine(self, "stateMachineId",
                definition=ssh_error_response_sfn_definition,
                timeout=core.Duration.minutes(5)
        )

        ###############################################################################
        ################# STEP FUNCTIONS EXPERIMENTAL CODE - UNSTABLE #################
        ###############################################################################

        # LAMBDA TO TRIGGER STATE MACHINE - since state cannot be invoked by SNS
        with open("lambda_src/trigger_state_machine.py", encoding="utf8") as fp:
            trigger_state_machine_fn_handler_code = fp.read()

        trigger_state_machine_fn = _lambda.Function(
            self,
            id='sshErrorResponseFnId',
            function_name="trigger_ssh_error_response_state_machine_fn",
            runtime=_lambda.Runtime.PYTHON_3_7,
            code=_lambda.InlineCode(trigger_state_machine_fn_handler_code),
            # code=_lambda.Code.asset("lambda_src/is_policy_permissive.py"),
            # code=_lambda.Code.asset('lambda_src'),
            # code=_lambda.InlineCode(code_body),
            handler='index.lambda_handler',
            timeout=core.Duration.seconds(5),
            environment={
                "STATE_MACHINE_ARN": f"{ssh_error_response_statemachine.state_machine_arn}",
            }
        )

        trigger_state_machine_fn_perms=_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            resources=[
                f"{ssh_error_response_statemachine.state_machine_arn}",
                ],
            actions=[
                "states:StartExecution"
            ]
        )
        trigger_state_machine_fn_perms.sid="PutBucketPolicy"
        trigger_state_machine_fn.add_to_role_policy( trigger_state_machine_fn_perms )

        """
        version = trigger_state_machine_fn.add_version(name=datetime.now().isoformat())
        trigger_state_machine_fn_alias = _lambda.Alias(self, 
            'lmdaAliasId',
            alias_name='MystiqueTestAlias',
            version=version
            )
        """


        # Lets add permission to SNS to trigger our lambda function
        trigger_lambda_perms=_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            resources=[
                trigger_state_machine_fn.function_arn,
                ],
            actions=[
                "lambda:InvokeFunction",
            ]
        )
        trigger_lambda_perms.sid="TriggerLambaFunction"
        # info_sec_ops_topic.add_to_resource_policy( trigger_lambda_perms )

        # Subscribe InfoSecOps Email to topic
        info_sec_ops_topic.add_subscription(_subs.EmailSubscription(global_args.INFO_SEC_OPS_EMAIL))
        # info_sec_ops_topic.add_subscription(_subs.LambdaSubscription(trigger_state_machine_fn))

        trigger_state_machine_fn_alarm = trigger_state_machine_fn.metric_all_errors().create_alarm(self, "fn-error-alarm",
                                                                    threshold=5,
                                                                    alarm_name="trigger_state_machine_fn_error_alarm",
                                                                    evaluation_periods=5,
                                                                    period=core.Duration.minutes(1),
                                                                    )


        subscribe_trigger_state_machine_fn_to_logs = _logs.SubscriptionFilter(
            self,
            "sshErrorLogSubscriptionId",
            log_group=info_sec_ops_log_group,
            destination=_logs_destination.LambdaDestination(trigger_state_machine_fn),
            filter_pattern=_logs.FilterPattern.space_delimited("Mon", "day", "timestamp", "ip", "id", "status", "...").where_string("status", "=", "Invalid"),
        )


        # https://pypi.org/project/aws-cdk.aws-logs/
        # We are creating three filter
        # tooManySshDisconnects, invalidSshUser and invalidSshKey:
        # When a user tries to SSH with invalid username the next line is logged in the SSH log file:
        # Apr 20 02:39:35 ip-172-31-63-56 sshd[17136]: Received disconnect from xxx.xxx.xxx.xxx: 11:  [preauth]
        too_many_ssh_disconnects_metric = _cloudwatch.Metric(
            namespace=f"{global_args.OWNER}",
            metric_name="tooManySshDisconnects"
        )
        too_many_ssh_disconnects_filter = _logs.MetricFilter(
            self,
            "tooManySshDisconnectsFilterId",
            log_group=info_sec_ops_log_group,
            metric_namespace=too_many_ssh_disconnects_metric.namespace,
            metric_name=too_many_ssh_disconnects_metric.metric_name,
            filter_pattern=_logs.FilterPattern.space_delimited("Mon", "day", "timestamp", "ip", "id", "msg1", "msg2", "...").where_string("msg2", "=", "disconnect"),
            metric_value="1"
        )

        invalid_ssh_user_metric = _cloudwatch.Metric(
            namespace=f"{global_args.OWNER}",
            metric_name="invalidSshUser",
        )
        invalid_ssh_user_filter = _logs.MetricFilter(
            self,
            "invalidSshUserFilterId",
            log_group=info_sec_ops_log_group,
            metric_namespace=invalid_ssh_user_metric.namespace,
            metric_name=invalid_ssh_user_metric.metric_name,
            filter_pattern=_logs.FilterPattern.space_delimited("Mon", "day", "timestamp", "ip", "id", "status", "...").where_string("status", "=", "Invalid"),
            metric_value="1"
        )

        invalid_ssh_key_metric = _cloudwatch.Metric(
            namespace=f"{global_args.OWNER}",
            metric_name="invalidSshKey"
        )

        invalid_ssh_key_filter = _logs.MetricFilter(
            self,
            "invalidSshKeyFilterId",
            log_group=info_sec_ops_log_group,
            metric_namespace=invalid_ssh_key_metric.namespace,
            metric_name=invalid_ssh_key_metric.metric_name,
            filter_pattern=_logs.FilterPattern.space_delimited("Mon", "day", "timestamp", "ip", "id", "msg1", "msg2", "...").where_string("msg1", "=", "Connection").where_string("msg2", "=", "closed"),
            metric_value="1"
        )

        # Now let us create alarms
        # alarm is raised there are more than 5(threshold) of the measured metrics in two(datapoint) of the last three seconds(evaluation):
        # Period=60Seconds, Eval=3, Threshold=5
        too_many_ssh_disconnects_alarm = _cloudwatch.Alarm(self, 
            "tooManySshDisconnectsAlarmId",
            alarm_name="too_many_ssh_disconnects_alarm",
            alarm_description="The number disconnect requests is greater then 5, even 1 time in 3 minutes",
            metric=too_many_ssh_disconnects_metric,
            actions_enabled=True,
            period=core.Duration.minutes(1),
            threshold=5,
            evaluation_periods=3,
            datapoints_to_alarm=1,
            statistic="sum",
            comparison_operator=_cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD
        )
    
        invalid_ssh_user_alarm = _cloudwatch.Alarm(self, 
            "invalidSshUserAlarmId",
            alarm_name="too_many_invalid_ssh_users_alarm",
            alarm_description="The number of invalid ssh users connecting is greater then 5, even 1 time in 3 minutes",
            metric=invalid_ssh_user_metric,
            actions_enabled=True,
            period=core.Duration.minutes(1),
            threshold=5,
            evaluation_periods=3,
            datapoints_to_alarm=1,
            statistic="sum",
            comparison_operator=_cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
        invalid_ssh_user_alarm.add_alarm_action(
            _cloudwatch_actions.SnsAction(info_sec_ops_topic)
        )


        invalid_ssh_key_alarm = _cloudwatch.Alarm(self, 
            "invalidSshKeyAlarmId",
            alarm_name="too_many_invalid_ssh_key_alarm",
            alarm_description="The number of invalid ssh keys connecting is greater then 5, even 1 time in 3 minutes",
            metric=invalid_ssh_key_metric,
            actions_enabled=True,
            period=core.Duration.minutes(1),
            threshold=5,
            evaluation_periods=3,
            datapoints_to_alarm=1,
            statistic="sum",
            comparison_operator=_cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD
        )
        invalid_ssh_key_alarm.add_alarm_action(
            _cloudwatch_actions.SnsAction(info_sec_ops_topic)
        )


        ###########################################
        ################# OUTPUTS #################
        ###########################################

        output0 = core.CfnOutput(self,
            "SecuirtyAutomationFrom",
            value=f"{global_args.SOURCE_INFO}",
            description="To know more about this automation stack, check out our github page."
            )

        output1_1 = core.Fn.get_att(logical_name_of_resource="sshMonitoredInstance01",attribute_name="PublicIp")
        output1 = core.CfnOutput(self,
            "MonitoredInstance",
            value=output1_1.to_string(),
            description="Web Server Public IP to attack"
        )

        output2 = core.CfnOutput(self,
            "SSHAlarms",
            value=(
                f"https://console.aws.amazon.com/cloudwatch/home?region="
                f"{core.Aws.REGION}"
                f"#/configuration/"
                f"#alarmsV2:?search=ssh&alarmStateFilter=ALL&alarmTypeFilter=ALL"
            ),
            description="Check out the cloudwatch Alarms"
        )

        output3 = core.CfnOutput(self,
            "SubscribeToNotificationTopic",
            value=(
                f"https://console.aws.amazon.com/sns/v3/home?"
                f"{core.Aws.REGION}"
                f"#/topic/"
                f"{info_sec_ops_topic.topic_arn}"
            ),
            description="Add your email to subscription and confirm subscription"
        )

        output_test_1 = core.CfnOutput(self,
            "ToGenInvalidKeyErrors",
            value=(
                f"for i in {{1..30}}; do ssh -i $RANDOM ec2-user@{output1_1.to_string()}; sleep 2; done &"
            ),
            description="Generates random key names and connects to server 30 times over 60 seconds"
        )

        output_test_2 = core.CfnOutput(self,
            "ToGenInvalidUserErrors",
            value=(
                f"for i in {{1..30}}; do ssh ec2-user$RANDOM@{output1_1.to_string()}; sleep 2; done &"
            ),
            description="Generates random user names and connects to server 30 times over 60 seconds"
        )  

        """
        aws logs put-log-events \
        --log-group-name MyApp/access.log --log-stream-name hostname \
        --log-events \
        timestamp=1394793518000,message="127.0.0.1 - bob [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 404 2326" \
        timestamp=1394793528000,message="127.0.0.1 - bob [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb2.gif HTTP/1.0\" 200 2326"        

        """
