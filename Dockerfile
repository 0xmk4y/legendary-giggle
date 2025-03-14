FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8000 for Gunicorn
EXPOSE 8000

# Run Flask using Gunicorn
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "app:app"]
