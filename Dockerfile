FROM python:3.12
RUN pip install flask requests bcrypt pyjwt elasticsearch
CMD ["sh", "-c", "python3 /home/app/elasticsearch_creation.py && python3 /home/app/app.py"]