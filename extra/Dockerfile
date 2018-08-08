FROM python:3.6-alpine3.7

WORKDIR /app

ENV KGEN="http://kindlegen.s3.amazonaws.com/kindlegen_linux_2.6_i386_v2_9.tar.gz" \
    DEPS="alpine-sdk openssl-dev libffi-dev libxml2-dev libxslt-dev" \
    USER_NAME="safaribooks" \
    USER_UID="10001"

RUN addgroup ${USER_NAME} && \
    adduser -h /app -u ${USER_UID} -G ${USER_NAME} -D ${USER_NAME}

# Copy required files
COPY requirements.txt safaribooks.py /app/

# Download kindlegen, move it and make it executable
RUN wget -qO- ${KGEN} | \
            tar -xzOf - kindlegen > /app/kindlegen && \
            chmod +x /app/kindlegen

# Install required system dependencies and python dependencies
RUN apk add --no-cache ${DEPS} && \
    pip3 install --no-cache-dir -r requirements.txt

COPY extra/run.sh /app/
RUN mkdir -p /app/converted && \
    chmod -R u+x /app && \
    chown -R ${USER_NAME}:0 /app && \
    chmod -R g=u /app && \
    chmod a+x /app/run.sh

USER ${USER_NAME}
VOLUME ["/app/converted"]
ENTRYPOINT ["/app/run.sh"]
