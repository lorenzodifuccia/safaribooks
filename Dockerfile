FROM python:3

RUN mkdir -p /safaribooks

WORKDIR /safaribooks

COPY . ./

RUN pip3 install -r requirements.txt

CMD ["python3", "safaribooks.py", "--no-cookies"]
