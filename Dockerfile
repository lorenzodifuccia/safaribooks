FROM python:3.6

WORKDIR /app

COPY requirements.txt ./
COPY Pipfile ./
COPY Pipfile.lock ./
COPY register_user.py ./
COPY safaribooks.py ./
COPY sso_cookies.py ./

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "python", "./safaribooks.py" ]