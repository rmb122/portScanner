FROM python:3.8

WORKDIR /app/

COPY ./backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/

COPY ./backend/ ./

CMD ["python", "./web.py"]
