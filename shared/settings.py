__V__ = "2020.V.02.39"

defaultdb = {
    "dbname": "urlsandbox",
    "reportscoll": "reports",
    "filescoll": "files",
    "userscoll": "users",
    "alllogscoll": "alllogs",
    "taskfileslogscoll": "taskfileslogs",
    "taskdblogscoll": "taskdblogs"
}

json_settings = {
    "docker": {
        "backend_key": "w9AMMSqmKo4gFfE3s!Ghy4cRbE]xiynWKJhoUN(!1IfsOpJ0Z1KypX2uXhfH(lsQQqQ92pvDobxBC_oc^3M,0EzuO2wGk9fzhO0aWpkzSA7WXf2kDKafLpevawhfxJa09=#OJmlCNJE9Fa107A@g1s",
        "mongo_settings_host": "mongodb",
        "mongo_settings": "mongodb://changeme_9620eh26sfvka017fx:changeme_0cx821ncf7qg17ahx3@mongodb:27017/?authSource=admin",
        "redis_settings": "redis://:changeme_927dhgs810d712fxs1@url-sandbox_redis:6379/0",
        "celery_settings": {
            "celery_broker_url": "redis://:changeme_927dhgs810d712fxs1@url-sandbox_redis:6379/0",
            "celery_result_backend": "redis://:changeme_927dhgs810d712fxs1@url-sandbox_redis:6379/0",
            "name": "tasks"
        },
        "url_timeout": 10,
        "analyzer_timeout": 60,
        "web_mongo": [{
            "ALIAS": "default",
            "DB": defaultdb["dbname"],
            "HOST": "mongodb://changeme_9620eh26sfvka017fx:changeme_0cx821ncf7qg17ahx3@mongodb:27017/urlsandbox?authSource=admin"
        }],
        "logs_folder": "/tmp/urlsandbox/logs/",
        "output_folder": "/tmp/urlsandbox/output/",
        "db_folder": "/tmp/urlsandbox/dbs/",
        "docker_volume_output": "url-sandbox_output",
        "retention_days": 60,
        "max_concurrent_vnc": 5,
        "task_logs": {
            "box_output": "/output/",
            "sniffer_logs": "-sniffer.logs",
            "analyzer_logs": "-analyzer.logs",
        },
        "worker": {
            "task_time_limit": 300,
            "name": "analyze_url",
            "queue": "analyze_url_queue"
        }
    }
}

meta_users_settings = {
    'db_alias': 'default',
    'collection': defaultdb["userscoll"],
    'strict': False
}

