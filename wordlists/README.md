# Wordlists

Las tres listas provienen de `raft-medium-directories.txt` de SecLists `2026.1`.
Las variantes rápida y estándar conservan, respectivamente, las primeras 1 500
y 10 000 entradas de la lista original ordenada:

- `raft-quick-directories.txt`: 1 500 entradas, 10 solicitudes/s.
- `raft-standard-directories.txt`: 10 000 entradas, 8 solicitudes/s.
- `raft-medium-directories.txt`: 29 999 entradas, 5 solicitudes/s.

Origen:

`Discovery/Web-Content/raft-medium-directories.txt`

SHA-256 fijados:

`a9626959f818d9e198259665c5a88053b7b061c538f46da215d172bcba305fe9`

`35689f52759bb7097bcffe86febed470ac09b31816e770417455e4022d8d35cc`

`b15a5c07c2c8a7a026868ee6929eaf2b65f2942c9e6780bc3a91deb124432c9b`

El archivo se conserva en el repositorio para que ffuf use exactamente la misma
lista en el CLI local y en la imagen. El `Containerfile` valida el checksum antes
de continuar la construcción.
