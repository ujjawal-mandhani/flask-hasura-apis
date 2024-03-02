FROM python:3.12
RUN pip install flask requests bcrypt pyjwt elasticsearch gunicorn
CMD ["sh", "-c", "python3 /home/app/elasticsearch_creation.py && cd /home/app/ && gunicorn -w 4 -b 0.0.0.0:23002 wsgi:app"]