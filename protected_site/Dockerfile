FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY protected_site/requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

COPY protected_site ./protected_site

RUN useradd --create-home --uid 10001 storefront && chown -R storefront:storefront /app

USER storefront

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9000/health', timeout=3)"]

CMD ["uvicorn", "protected_site.app:app", "--host", "0.0.0.0", "--port", "9000"]
