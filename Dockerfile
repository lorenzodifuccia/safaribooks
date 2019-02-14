FROM python:3.7.2-alpine3.8 as builder
ENV PYTHONUNBUFFERED 1
RUN apk add --no-cache --upgrade \
    build-base \
    libxml2-dev \
    libxslt-dev
WORKDIR /wheels
COPY ./requirements.txt /wheels/requirements.txt
RUN pip install -U pip \
    && pip wheel -r requirements.txt

# ---

FROM python:3.7.2-alpine3.8
ENV PYTHONUNBUFFERED 1
COPY --from=builder /wheels /wheels
RUN pip install -U pip \
    && pip install -r /wheels/requirements.txt -f /wheels \
    && rm -rf /wheels \
    && rm -rf /root/.cache/pip/*
RUN apk add --no-cache --upgrade \
    libxml2 \
    libxslt
WORKDIR /safaribooks
COPY . /safaribooks
ENTRYPOINT ["./entrypoint.sh"]
CMD ["--help"]
