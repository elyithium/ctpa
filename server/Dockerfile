# Use a Python base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app
COPY . /app
# Copy the current directory contents into the container at /app

RUN pip install -r requirements.txt


EXPOSE 5000

ENV PYTHONNUNBUFFRED=1
# Run vulnerability scanner script when the container launches
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "server:app"]
