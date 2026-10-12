def search(db, term):
    return db.execute("SELECT id, name FROM products WHERE public = 1 AND name LIKE ?",
                      ("%" + term + "%",)).fetchall()
