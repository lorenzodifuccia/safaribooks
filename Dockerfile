FROM python:latest

COPY . /safaribooks

WORKDIR /safaribooks

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "/safaribooks/safaribooks.py"]

