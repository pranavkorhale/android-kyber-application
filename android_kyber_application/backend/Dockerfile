FROM python:3.10-slim

# Install system dependencies for building liboqs
RUN apt-get update && apt-get install -y \
    git \
    cmake \
    gcc \
    g++ \
    libssl-dev \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
WORKDIR /app
COPY requirements.txt .
# Remove the manual liboqs note if present or just install others
RUN pip install --no-cache-dir fastapi uvicorn websockets pydantic

# Build and Install liboqs (C Library)
WORKDIR /tmp
RUN git clone --branch main --single-branch https://github.com/open-quantum-safe/liboqs.git \
    && cd liboqs \
    && mkdir build \
    && cd build \
    && cmake -GNinja -DOQS_USE_OPENSSL=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. \
    && ninja \
    && ninja install \
    && ldconfig

# Install liboqs-python wrapper
WORKDIR /tmp
RUN git clone --branch main --single-branch https://github.com/open-quantum-safe/liboqs-python.git \
    && cd liboqs-python \
    && pip install .

# Setup App
WORKDIR /app
COPY . .
COPY start.sh .
RUN chmod +x start.sh

# Run server
CMD ["./start.sh"]
