# Python base image
FROM python:3.13-slim

# Set the working directory
WORKDIR /app

# Copy application files
COPY . /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port the app will listen on
EXPOSE 8080

# Command to start the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
