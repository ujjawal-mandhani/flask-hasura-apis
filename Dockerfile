FROM python:3.12
RUN pip install flask requests bcrypt pyjwt
CMD ["sh", "-c", "python3 /home/app/app.py"]