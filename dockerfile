FROM python:3

WORKDIR /reviewers

COPY requirements.txt ./
RUN apt update -y &&  pip install --no-cache-dir -r requirements.txt

COPY . .

ENV ELASTICSEARCH_HOST="elasticsearch" \
    ELASTICSEARCH_PORT=9200 \
    ELASTICSEARCH_USERNAME="elastic" \
    ELASTICSEARCH_PW="elastic" \
    ELASTICSEARCH_MAX_RESULT=1000000000 \
    RABBITMQ_HOST="rabbitmq" \
    RABBITMQ_MANAGEMENT_PORT=15672 \
    RABBITMQ_OPERATION_PORT=5672 \
    RABBITMQ_QUEUE_NAME_LISTEN="modsecurity-raw" \
    RABBITMQ_QUEUE_NAME_ANSWER="modsecurity-rules" \
    RABBITMQ_USERNAME="guest" \
    RABBITMQ_PW="guest"

CMD [ "python", "./run.py" ]
