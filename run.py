from elasticsearch import Elasticsearch
from json import dumps, loads
from logging import info, warning, error, basicConfig, INFO
from os import getenv, _exit
from pika import BlockingConnection, ConnectionParameters, PlainCredentials
from requests import get
from sys import exit
from time import sleep


basicConfig(format=dumps({
    'datetime': '%(asctime)s',
    'loglevel': '[%(levelname)s]',
    'message': '%(message)s'
}), datefmt='%H:%M:%S %d/%m/%Y', level=INFO)

ELASTICSEARCH_HOST         = getenv(key='ELASTICSEARCH_HOST')
ELASTICSEARCH_PORT         = getenv(key='ELASTICSEARCH_PORT')
ELASTICSEARCH_USERNAME     = getenv(key='ELASTICSEARCH_USERNAME')
ELASTICSEARCH_PW           = getenv(key='ELASTICSEARCH_PW')
ELASTICSEARCH_MAX_RESULT   = getenv(key='ELASTICSEARCH_MAX_RESULT')

RABBITMQ_HOST              = getenv(key='RABBITMQ_HOST')
RABBITMQ_MANAGEMENT_PORT   = getenv(key='RABBITMQ_MANAGEMENT_PORT')
RABBITMQ_OPERATION_PORT    = getenv(key='RABBITMQ_OPERATION_PORT')
RABBITMQ_QUEUE_NAME_LISTEN = getenv(key='RABBITMQ_QUEUE_NAME_LISTEN')
RABBITMQ_QUEUE_NAME_ANSWER = getenv(key='RABBITMQ_QUEUE_NAME_ANSWER')
RABBITMQ_USERNAME          = getenv(key='RABBITMQ_USERNAME')
RABBITMQ_PASSWORD          = getenv(key='RABBITMQ_PW')


def main():
    elasticsearch_response = connect_elasticsearch()
    if check_env() is False or elasticsearch_response is False or check_rabbitmq() is False:
        return
    processor(elasticsearch_response=elasticsearch_response)


def check_env():
    info(msg='Checking environment variables...')
    env_vars = {
        'ELASTICSEARCH_HOST': ELASTICSEARCH_HOST,
        'ELASTICSEARCH_PORT': ELASTICSEARCH_PORT,
        'ELASTICSEARCH_USERNAME': ELASTICSEARCH_USERNAME,
        'ELASTICSEARCH_PW': ELASTICSEARCH_PW,
        'ELASTICSEARCH_MAX_RESULT': ELASTICSEARCH_MAX_RESULT,
        'RABBITMQ_HOST': RABBITMQ_HOST,
        'RABBITMQ_MANAGEMENT_PORT': RABBITMQ_MANAGEMENT_PORT,
        'RABBITMQ_OPERATION_PORT': RABBITMQ_OPERATION_PORT,
        'RABBITMQ_QUEUE_NAME_LISTEN': RABBITMQ_QUEUE_NAME_LISTEN,
        'RABBITMQ_QUEUE_NAME_ANSWER': RABBITMQ_QUEUE_NAME_ANSWER,
        'RABBITMQ_USERNAME': RABBITMQ_USERNAME,
        'RABBITMQ_PW': RABBITMQ_PASSWORD,
    }
    if not all([value for _, value in env_vars.items()]):
        error(msg=f'Missing required variables: {[key for key, value in env_vars.items() if not value]}')
        return False
    info(msg='Environment variables [OK]')
    return True


def connect_elasticsearch():
    info(msg='Checking Elasticsearch...')
    try:
        elasticsearch_response = Elasticsearch(
            hosts=f'http://{ELASTICSEARCH_HOST}:{ELASTICSEARCH_PORT}', 
            basic_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PW)
        )
    except ValueError as error_exception:
        error(msg=str(error_exception))
        return False
    while True:
        if elasticsearch_response.ping() is False:
            warning(msg='Ping to Elasticsearch fail, re-ping after 5 seconds')
            sleep(5)
        else:
            break
    info(msg='Elasticsearch [OK]')
    index_settings = {
        "settings": {
            "index": {
                "max_result_window": int(ELASTICSEARCH_MAX_RESULT)
            }
        }
    }
    info(msg='Checking "responser-modsecurity-executions" index...')
    if not elasticsearch_response.indices.exists(index='responser-modsecurity-executions'):
        info(msg='Creating "responser-modsecurity-executions"')
        elasticsearch_response.indices.create(index="responser-modsecurity-executions", body=index_settings)
        info(msg='Created "responser-modsecurity-executions"')
    info(msg='"responser-modsecurity-executions" [OK]')
    return elasticsearch_response


def check_rabbitmq():
    info(msg='Checking RabbitMQ...')
    try:
        rabbitmq_response = get(
            url=f'http://{RABBITMQ_HOST}:{RABBITMQ_MANAGEMENT_PORT}/api/healthchecks/node', 
            auth=(RABBITMQ_USERNAME, RABBITMQ_PASSWORD)
        )
        if rabbitmq_response.status_code != 200:
            error(msg=f'RabbitMQ connection testing fail, status code {rabbitmq_response.status_code}')
            return False
    except:
        error(msg='Can\'t perform GET request to RabbitMQ, fail for connection testing')
        return False
    info(msg='RabbitMQ [OK]')
    return True


def processor(elasticsearch_response: Elasticsearch):
    connection = BlockingConnection(
        ConnectionParameters(
            host=RABBITMQ_HOST,
            port=RABBITMQ_OPERATION_PORT,
            credentials=PlainCredentials(
                username=RABBITMQ_USERNAME,
                password=RABBITMQ_PASSWORD
            )
        )
    )
    channel = connection.channel()
    channel.queue_declare(queue=RABBITMQ_QUEUE_NAME_LISTEN, durable=True)
    channel.queue_declare(queue=RABBITMQ_QUEUE_NAME_ANSWER, durable=True)
    def callback(ch, method, properties, body: bytes):
        request_body: dict = loads(body.decode())
        responser_name = request_body.get('responser_name')
        modsec_type = request_body.get('type')
        details: dict = request_body.get('details')
        detail_ip = details.get('ip')
        detail_ip_source = None
        if detail_ip is not None:
            detail_ip_source = detail_ip.get('source_ip')
        detail_hashed_rule = details.get('hashed_rule')
        detail_hashed_payload = details.get('hashed_payload')
        payload = request_body.get('payload')
        modsecurity_executions = elasticsearch_response.search(index='responser-modsecurity-executions', query={'match_all': {}}, size=ELASTICSEARCH_MAX_RESULT).raw['hits']['hits']
        if modsec_type == 'full':
            if [
                entity for entity in modsecurity_executions
                if entity['_source']['detail_ip'] == detail_ip_source
                and entity['_source']['detail_hashed_rule'] == detail_hashed_rule
                and entity['_source']['detail_hashed_payload'] == detail_hashed_payload
            ].__len__() > 0:
                process_double_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=detail_ip_source,
                    detail_hashed_rule=detail_hashed_rule,
                    detail_hashed_payload=detail_hashed_payload,
                    status='duplicated',
                    payload=payload
                )
            else:
                modsecurity_execution = process_double_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=detail_ip_source,
                    detail_hashed_rule=detail_hashed_rule,
                    detail_hashed_payload=detail_hashed_payload,
                    status='waiting',
                    payload=payload
                )
                request_body['execution_id'] = None
                request_body['execution_id_for_ip'] = modsecurity_execution[0]
                request_body['execution_id_for_chain'] = modsecurity_execution[1]
                channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps(request_body))
        if modsec_type == 'onlyRegexAndPayload':
            if [
                entity for entity in modsecurity_executions
                if entity['_source']['detail_ip'] is None
                and entity['_source']['detail_hashed_rule'] == detail_hashed_rule
                and entity['_source']['detail_hashed_payload'] == detail_hashed_payload
            ].__len__() > 0:
                process_single_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=None,
                    detail_hashed_rule=detail_hashed_rule,
                    detail_hashed_payload=detail_hashed_payload,
                    status='duplicated',
                    payload=payload
                )
            else:
                modsecurity_execution = process_single_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=None,
                    detail_hashed_rule=detail_hashed_rule,
                    detail_hashed_payload=detail_hashed_payload,
                    status='waiting',
                    payload=payload
                )
                request_body['execution_id'] = modsecurity_execution[0]
                request_body['execution_id_for_ip'] = None
                request_body['execution_id_for_chain'] = None
                channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps(request_body))
        if modsec_type == 'onlyPayload':
            if [
                entity for entity in modsecurity_executions
                if entity['_source']['detail_ip'] is None
                and entity['_source']['detail_hashed_rule'] is None
                and entity['_source']['detail_hashed_payload'] == detail_hashed_payload
            ].__len__() > 0:
                process_single_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=None,
                    detail_hashed_rule=None,
                    detail_hashed_payload=detail_hashed_payload,
                    status='duplicated',
                    payload=payload
                )
            else:
                modsecurity_execution = process_single_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=None,
                    detail_hashed_rule=None,
                    detail_hashed_payload=detail_hashed_payload,
                    status='waiting',
                    payload=payload
                )
                request_body['execution_id'] = modsecurity_execution[0]
                request_body['execution_id_for_ip'] = None
                request_body['execution_id_for_chain'] = None
                channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps(request_body))
        if modsec_type == 'onlyIP':
            if [
                entity for entity in modsecurity_executions
                if entity['_source']['detail_ip'] == detail_ip_source
                and entity['_source']['detail_hashed_rule'] is None
                and entity['_source']['detail_hashed_payload'] is None
            ].__len__() > 0:
                process_single_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=detail_ip_source,
                    detail_hashed_rule=None,
                    detail_hashed_payload=None,
                    status='duplicated',
                    payload=payload
                )
            else:
                modsecurity_execution = process_single_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=detail_ip_source,
                    detail_hashed_rule=None,
                    detail_hashed_payload=None,
                    status='waiting',
                    payload=payload
                )
                request_body['execution_id'] = modsecurity_execution[0]
                request_body['execution_id_for_ip'] = None
                request_body['execution_id_for_chain'] = None
                channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps(request_body))
        if modsec_type == 'onlyIPAndPayload':
            if [
                entity for entity in modsecurity_executions
                if entity['_source']['detail_ip'] == detail_ip_source
                and entity['_source']['detail_hashed_rule'] is None
                and entity['_source']['detail_hashed_payload'] == detail_hashed_payload
            ].__len__() > 0:
                process_double_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=detail_ip_source,
                    detail_hashed_rule=None,
                    detail_hashed_payload=detail_hashed_payload,
                    status='duplicated',
                    payload=payload
                )
            else:
                modsecurity_execution = process_double_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=detail_ip_source,
                    detail_hashed_rule=None,
                    detail_hashed_payload=detail_hashed_payload,
                    status='waiting',
                    payload=payload
                )
                request_body['execution_id'] = None
                request_body['execution_id_for_ip'] = modsecurity_execution[0]
                request_body['execution_id_for_chain'] = modsecurity_execution[1]
                channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps(request_body))
        if modsec_type == 'onlyIPAndRegex':
            if [
                entity for entity in modsecurity_executions
                if entity['_source']['detail_ip'] == detail_ip_source
                and entity['_source']['detail_hashed_rule'] == detail_hashed_rule
                and entity['_source']['detail_hashed_payload'] is None
            ].__len__() > 0:
                process_double_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=detail_ip_source,
                    detail_hashed_rule=detail_hashed_rule,
                    detail_hashed_payload=None,
                    status='duplicated',
                    payload=payload
                )
            else:
                modsecurity_execution = process_double_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=detail_ip_source,
                    detail_hashed_rule=detail_hashed_rule,
                    detail_hashed_payload=None,
                    status='waiting',
                    payload=payload
                )
                request_body['execution_id'] = None
                request_body['execution_id_for_ip'] = modsecurity_execution[0]
                request_body['execution_id_for_chain'] = modsecurity_execution[1]
                channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps(request_body))
        if modsec_type == 'onlyRegex':
            if [
                entity for entity in modsecurity_executions
                if entity['_source']['detail_ip'] is None
                and entity['_source']['detail_hashed_rule'] == detail_hashed_rule
                and entity['_source']['detail_hashed_payload'] is None
            ].__len__() > 0:
                process_single_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=None,
                    detail_hashed_rule=detail_hashed_rule,
                    detail_hashed_payload=None,
                    status='duplicated',
                    payload=payload
                )
            else:
                modsecurity_execution = process_single_secrule(
                    elasticsearch_response=elasticsearch_response,
                    responser_name=responser_name,
                    modsec_type=modsec_type,
                    detail_ip=None,
                    detail_hashed_rule=detail_hashed_rule,
                    detail_hashed_payload=None,
                    status='waiting',
                    payload=payload
                )
                request_body['execution_id'] = modsecurity_execution[0]
                request_body['execution_id_for_ip'] = None
                request_body['execution_id_for_chain'] = None
                channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps(request_body))
        ch.basic_ack(delivery_tag=method.delivery_tag)
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=RABBITMQ_QUEUE_NAME_LISTEN, on_message_callback=callback)
    channel.start_consuming()


def process_single_secrule(
    elasticsearch_response: Elasticsearch,
    responser_name: str,
    modsec_type: str,
    detail_ip: str,
    detail_hashed_rule: str,
    detail_hashed_payload: str,
    status: str,
    payload: str
):
    modsecurity_execution = elasticsearch_response.index(index='responser-modsecurity-executions', document={
        'responser_name': responser_name,
        'secrule_id': None,
        'type': modsec_type,
        'for': None,
        'start': None,
        'detail_ip': detail_ip,
        'anomaly_score': None,
        'paranoia_level': None,
        'detail_rule': None,
        'detail_payload': None,
        'detail_hashed_rule': detail_hashed_rule,
        'detail_hashed_payload': detail_hashed_payload,
        'payload': dumps(payload),
        'relationship': None,
        'real_id_relationship': None,
        'status': status
    }, refresh='wait_for')
    return (
        modsecurity_execution['_id'],
    )


def process_double_secrule(
    elasticsearch_response: Elasticsearch,
    responser_name: str,
    modsec_type: str,
    detail_ip: str,
    detail_hashed_rule: str,
    detail_hashed_payload: str,
    status: str,
    payload: str
):
    modsecurity_execution_for_ip = elasticsearch_response.index(index='responser-modsecurity-executions', document={
        'responser_name': responser_name,
        'secrule_id': None,
        'type': modsec_type,
        'for': 'ip',
        'start': None,
        'detail_ip': detail_ip,
        'anomaly_score': None,
        'paranoia_level': None,
        'detail_rule': None,
        'detail_payload': None,
        'detail_hashed_rule': detail_hashed_rule,
        'detail_hashed_payload': detail_hashed_payload,
        'payload': dumps(payload),
        'relationship': None,
        'real_id_relationship': None,
        'status': status
    }, refresh='wait_for')
    modsecurity_execution_for_chain = elasticsearch_response.index(index='responser-modsecurity-executions', document={
        'responser_name': responser_name,
        'secrule_id': None,
        'type': modsec_type,
        'for': 'chain',
        'start': None,
        'detail_ip': detail_ip,
        'anomaly_score': None,
        'paranoia_level': None,
        'detail_rule': None,
        'detail_payload': None,
        'detail_hashed_rule': detail_hashed_rule,
        'detail_hashed_payload': detail_hashed_payload,
        'payload': dumps(payload),
        'relationship': None,
        'real_id_relationship': modsecurity_execution_for_ip['_id'],
        'status': status
    }, refresh='wait_for')
    elasticsearch_response.update(
        index='responser-modsecurity-executions',
        id=modsecurity_execution_for_ip['_id'],
        doc={
            'real_id_relationship': modsecurity_execution_for_chain['_id']
        },
        refresh='wait_for'
    )
    return (
        modsecurity_execution_for_ip['_id'],
        modsecurity_execution_for_chain['_id']
    )


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        try:
            exit(0)
        except SystemExit:
            _exit(0)
