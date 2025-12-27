FROM continuumio/miniconda3

WORKDIR /app

# Copy file môi trường vào trước để tận dụng cache của Docker
COPY environment.yml .

# Khởi tạo môi trường từ file yml
RUN conda env create -f environment.yml

# Đảm bảo lệnh python chạy trong môi trường p2p-chat-env
SHELL ["conda", "run", "-n", "p2p-chat-env", "/bin/bash", "-c"]

COPY peer.py .

# Chạy ứng dụng thông qua conda run
ENTRYPOINT ["conda", "run", "--no-capture-output", "-n", "p2p-chat-env", "python", "peer.py"]