class BorrowLimitExceeded(Exception):
    pass

class BookNotAvailableError(Exception):
    pass

class Book:
    def __init__(self, book_id, title, author, category):      
        self.book_id = book_id
        self.title = title
        self.author = author
        
        self.category = category
        self._is_available = True

    def is_available(self):
        return self._is_available

    def set_availability(self, value):
        self._is_available = value

    def mark_borrowed(self):
        self._is_available = False

    def mark_returned(self):
        self._is_available = True

    def __str__(self):
        status = "Available" if self._is_available else "Borrowed"
        return f"{self.book_id} | {self.title} | {self.author} | {self.category} | {status}"

class User:
    def __init__(self, user_id, name):
        self.user_id = user_id
        self.name = name
        self.borrowed_books = []

    def get_borrow_limit(self):
        return 3

    def borrow_book(self, book):

        if len(self.borrowed_books) >= self.get_borrow_limit():
            raise BorrowLimitExceeded("Borrow limit reached")

        if not book.is_available():
            raise BookNotAvailableError(book.title + " not available")

        book.mark_borrowed()
        self.borrowed_books.append(book)
        print(f"{self.name} borrowed {book.title}")

    def return_book(self, book):
        if book not in self.borrowed_books:
            print("Book not borrowed by user")
            return

        book.mark_returned()
        self.borrowed_books.remove(book)
        print(f"{self.name} returned {book.title}")


class StudentUser(User):
    def get_borrow_limit(self):
        return 3


class TeacherUser(User):
    def get_borrow_limit(self):
        return 5


class Library:
    def __init__(self):
        self.books = []
        self.users = []

    def add_book(self, book):
        self.books.append(book)

    def add_user(self, user):
        self.users.append(user)

    def get_book(self, book_id):
        for b in self.books:
            if b.book_id == book_id:
                return b
        return None

    def get_user(self, user_id):
        for u in self.users:
            if u.user_id == user_id:
                return u
        return None

    def borrow(self, book_id, user_id):

        book = self.get_book(book_id)
        user = self.get_user(user_id)

        if not book:
            print("Book not found")
            return

        if not user:
            print("User not found")
            return

        try:
            user.borrow_book(book)

        except BorrowLimitExceeded as e:
            print("Error:", e)

        except BookNotAvailableError as e:
            print("Error:", e)

    def search(self, keyword):
        keyword = keyword.lower()

        results = [
            b for b in self.books
            if keyword in b.title.lower()
            or keyword in b.author.lower()
            or keyword in b.category.lower()
        ]

        print(f"\nSearch results for '{keyword}' -> {len(results)} books found")
        for b in results:
            print(b)


print("\nWelcome to Smart Library System!")

lib = Library()

books = [
    Book(1, "JURASIC PARK", "ANTONY", "Science"),
    Book(2, "EVOLUTION OF SCIENCE", "BELIGUM", "Science"),
    Book(3, "History of India", "CHIRAJ", "History"),
    Book(4, "Python", "BJ PATEL", "Tech"),
    Book(5, "Math", "ED SHARMA", "Education"),
]

for b in books:
    lib.add_book(b)

print("Added 5 books.")

student = StudentUser(1, "Student")
teacher = TeacherUser(2, "Teacher")

lib.add_user(student)
lib.add_user(teacher)

print("Added 2 users.")


print("\nStudent tries to borrow 4 books -> Error")

for i in [1, 2, 3, 4]:
    lib.borrow(i, 1)


for b in books:
    b.mark_returned()

print("\nTeacher borrows 5 books -> Success")

for i in [1, 2, 3, 4, 5]:
    lib.borrow(i, 2)

print("\nBorrowing unavailable book -> Error")

lib.borrow(1, 1)

lib.search("science") 
 
 
