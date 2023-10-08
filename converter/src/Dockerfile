FROM python:3.10-alpine

# install packages
RUN apk update
RUN apk add --no-cache gcc musl-dev python3-dev libffi-dev freetype-dev

# permissions and ctf user stuff
RUN adduser -D ctf
RUN mkdir /home/app/ && chown -R ctf:ctf /home/app
WORKDIR /home/app
USER ctf

# copy all the files to the container
COPY --chown=ctf:ctf . .

RUN chmod -R 555 /home/app
RUN chmod +w /home/app/main/views.py

ENV PATH="/home/ctf/.local/bin:$PATH"

RUN pip install --upgrade pip
RUN pip install -r requirements.txt
CMD ["gunicorn", "-w", "6", "-t", "0", "-b", "0.0.0.0:8000", "chall.wsgi:application"]
