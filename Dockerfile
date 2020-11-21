FROM python:3.6

ADD requirements.txt /safaribooks/requirements.txt
WORKDIR /safaribooks
RUN pip3 install -r requirements.txt