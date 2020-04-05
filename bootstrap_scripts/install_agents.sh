#!/bin/bash -xe

# Lets log everything to console for being lazy (not recommended)
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

# install httpd
yum install httpd ec2-instance-connect -y

# Installing SSM Agent
mkdir -p /tmp/ssm \
    && yum install -y curl \
    && curl https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm -o /tmp/ssm/amazon-ssm-agent.rpm \
    && sudo yum install -y /tmp/ssm/amazon-ssm-agent.rpm \
    && sudo systemctl restart amazon-ssm-agent

# Installing AWS CloudWatch Agent FOR AMAZON LINUX RPM
agent_dir="/tmp/cw_agent"
cw_agent_rpm="https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm"
mkdir -p ${agent_dir} \
    && cd ${agent_dir} \
    && sudo yum install -y curl \
    && curl ${cw_agent_rpm} -o ${agent_dir}/amazon-cloudwatch-agent.rpm \
    && sudo rpm -U ${agent_dir}/amazon-cloudwatch-agent.rpm


cw_agent_schema="/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json"

cat > '/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json' << "EOF"
{
  "agent": {
    "metrics_collection_interval": 5,
    "logfile": "/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log"
  },
  "metrics": {
    "metrics_collected": {
      "mem": {
        "measurement": [
          "mem_used_percent"
        ]
      }
    },
    "append_dimensions": {
      "ImageId": "${aws:ImageId}",
      "InstanceId": "${aws:InstanceId}",
      "InstanceType": "${aws:InstanceType}"
    },
    "aggregation_dimensions": [
      [
        "InstanceId",
        "InstanceType"
      ],
      []
    ]
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/secure",
            "log_group_name": "/Mystique/InfoSec/Automation/{instance_id}",
            "timestamp_format": "%b %-d %H:%M:%S",
            "timezone": "Local"
          }
        ]
      }
    },
    "log_stream_name": "{instance_id}"
  }
}
EOF

# Configure the agent to monitor ssh log file
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:${cw_agent_schema} -s
# Start the CW Agent
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status

# Just in case we need to troubleshoot
cd "/opt/aws/amazon-cloudwatch-agent/logs/"

# sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a stop
