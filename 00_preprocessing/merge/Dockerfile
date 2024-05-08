FROM python:3.10.10-buster
RUN apt-get update
RUN apt install default-jre -y
WORKDIR /
COPY requirements.txt ./
RUN pip install --no-cache-dir -r /requirements.txt
COPY APKEditor-1.3.6.jar /APKEditor-1.3.6.jar
RUN chmod +x /APKEditor-1.3.6.jar
COPY . /