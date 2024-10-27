# Use a Python base image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install required Python packages
RUN pip install --no-cache-dir requests colorama pyOpenSSL argparse

# Ensure permissions for the working directory
RUN chmod -R 755 /app

# Run vulnerability scanner script when the container launches
CMD ["python", "main.py", "--interactive"]
