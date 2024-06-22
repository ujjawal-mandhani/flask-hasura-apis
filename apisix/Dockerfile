FROM apache/apisix
USER root
RUN apt update && apt upgrade -y
RUN apt install python3 python3-pip curl -y 
RUN pip install requests
USER apisix
COPY make_routes_conf.py /home/make_routes_conf.py
ENTRYPOINT [""]
CMD [ "sh", "-c", "sleep 20 && (/docker-entrypoint.sh docker-start & python3 /home/make_routes_conf.py) && tail -f /dev/null" ]