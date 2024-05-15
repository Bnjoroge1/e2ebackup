FROM ubuntu:20.04

# Avoiding user interaction with tzdata, etc.
ENV DEBIAN_FRONTEND=noninteractive

# Update and install necessary packages
RUN apt-get update && apt-get install -y \
    wget \
    lsb-release \
    software-properties-common \
    python3 \
    python3-pip
#install all python dependencies
COPY requirements.txt /tmp/
RUN pip3 install -r /tmp/requirements.txt

COPY . /app
WORKDIR /app

EXPOSE 8000 8501
# Install AWS CloudHSM Client(on Ubuntu Linux OS)
RUN wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Ubuntu20.04LTS/cloudhsm-client-latest.deb
RUN dpkg -i cloudhsm-client-latest.deb || apt-get install -f -y
RUN apt-get clean

# Set up the client
COPY setup_script.sh /root/setup_script.sh
RUN chmod +x /root/setup_script.sh
RUN /root/setup_script.sh
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh



# Command to run your application
CMD ["/app/start.sh"]

