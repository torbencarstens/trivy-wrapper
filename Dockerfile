FROM aquasec/trivy:0.28.1 as trivy

FROM python:3.10

COPY --from=trivy /usr/local/bin/trivy /usr/bin/trivy
RUN adduser --shell /bin/false \
            --uid 1000 \
            --gecos "" \
            --disabled-password\
            --disabled-login worker

USER 1000
WORKDIR /usr/src/app

COPY --chown=worker trivy/ trivy/
COPY --chown=worker requirements.txt .

RUN pip install --no-cache-dir --user -r requirements.txt

COPY --chown=worker main.py .
COPY --chown=worker trivy_templates templates

CMD ["python", "main.py", "--quiet", "kubernetes-images"]
