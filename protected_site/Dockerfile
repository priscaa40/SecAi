FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY protected_site/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY protected_site ./protected_site

EXPOSE 9000

CMD ["uvicorn", "protected_site.app:app", "--host", "0.0.0.0", "--port", "9000"]
