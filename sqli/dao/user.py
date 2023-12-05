from hashlib import md5, , scrypt, sha256
from typing import NamedTuple, , Optional
from aiopg import Connection
    id: int
    first_name: str
    last_name: str
    username: str
    pwd_hash: str
    is_admin: bool
    @classmethod
    def from_raw(cls, raw: tuple):
        return cls(*raw) if raw else None
    @staticmethod
    async def get(conn: Connection, id_: int):
        async with conn.cursor() as cur:
            await cur.execute(
                'SELECT id, first_name, middle_name, last_name, '
                'username, pwd_hash, is_admin FROM users WHERE id = %s',
                (id_,),
            )
            return User.from_raw(await cur.fetchone())
    @staticmethod
    async def get_by_username(conn: Connection, username: str):
        async with conn.cursor() as cur:
            await cur.execute(
                'SELECT id, first_name, middle_name, last_name, '
                'username, pwd_hash, is_admin FROM users WHERE username = %s',
                (username,),
            )
            return User.from_raw(await cur.fetchone())
    def check_password(self, password: str):
        # Use scrypt instead of MD5 or SHA256 for hashing the password
        # Note: The parameters for scrypt (n, r, p) should be chosen carefully based on the system's capabilities
        # to balance security and performance. The following values are placeholders and should be adjusted.
        n = 16384  # CPU/memory cost parameter (must be a power of 2, > 1)
        r = 8      # Block size parameter
        p = 1      # Parallelization parameter
        salt = b'some_random_salt'  # A proper salt should be unique for each password and securely generated
        key_len = 64  # Length of the generated hash
        # Generate the hash using scrypt and compare it to the stored hash
        hash = scrypt(password.encode('utf-8'), salt=salt, n=n, r=r, p=p, maxmem=0, dklen=key_len)
        return self.pwd_hash == hash.hex()
# Note: When setting or updating a user's password, you should also use scrypt to hash the new password before storing it in the database.
# Additionally, you will need to store the salt alongside the hashed password and use the same salt when verifying the password.
        return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()