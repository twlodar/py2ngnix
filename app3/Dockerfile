FROM python:3.12-slim
#WORKDIR /app
#COPY app.py .
#CMD ["python", "app.py"]

# Use an official Python runtime as a parent image
#FROM python:3.11-slim-bookworm
# Set the working directory in the container
WORKDIR /app
# Copy the requirements file (if you have one)
# COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# RUN pip install --no-cache-dir -r requirements.txt
# Install required packages (if no requirements.txt)
RUN apk add --no-cache openssh-client
RUN pip install --no-cache-dir paramiko google-generativeai PyYAML Flask Flask-CORS markupsafe
#jinja2 ewqe241242rwer
#RUN pip install --no-cache-dir --upgrade jinja2  # Add this line to upgrade Jinja2

# Copy the Python script and configuration files into the container
COPY router_log_analyzer.py .
COPY secrets.yaml .
COPY secret_gemini.yaml .
COPY ./templates ./templates  

# Expose the port the Flask app will run on (default: 5000)
EXPOSE 5000

# Set environment variables (optional, but recommended for API key)
# ENV GEMINI_API_KEY="YOUR_GEMINI_API_KEY"  #  <--  DO NOT HARDCODE!  Use docker run -e ...

# Command to run the Flask app
CMD ["python", "router_log_analyzer.py"]
