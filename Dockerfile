FROM alpine:3.5

RUN apk add --no-cache build-base python3-dev

RUN apk add --no-cache python3 && \
    python3 -m ensurepip && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install --upgrade pip setuptools && \
    rm -r /root/.cache

RUN pip3 install gunicorn
    
COPY . /usr/src/linkapp.authentication
RUN pip3 install /usr/src/linkapp.authentication
COPY wsgi.py /usr/src/app/

EXPOSE 8000

WORKDIR /usr/src/app

CMD ["gunicorn", "-b", "0.0.0.0:8000", "wsgi:app"]