from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from sqlmodel import Field, SQLModel, Session, create_engine, Relationship, select
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
import threading

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Product(SQLModel, table=True):
    id: Optional[int] = Field(primary_key=True, index=True)
    name: str
    price: float
    description: str = None
    stock_quantity: List['OrderItem'] = Relationship(back_populates='product')

class Customer(SQLModel, table=True):
    id: Optional[int] = Field(primary_key=True, index=True)
    name: str
    surname: str
    email: str
    username: str
    password: str
    address: str = None
    phone_number: str = None
    orders: List['Order'] = Relationship(back_populates='customer')

class Order(SQLModel, table=True):
    id: Optional[int] = Field(primary_key=True, index=True)
    customer_id: Optional[int] = Field(default=None, foreign_key="customer.id")
    order_date: datetime = Field(default_factory=datetime.utcnow)
    total_amount: float
    customer: Optional[Customer] = Relationship(back_populates='orders')
    order_items: List['OrderItem'] = Relationship(back_populates='order')

class OrderItem(SQLModel, table=True):
    id: Optional[int] = Field(primary_key=True, index=True)
    quantity: int
    price_per_unit: float
    total_price: float
    order_id: int = Field(default=None, primary_key=True, foreign_key='order.id')
    product_id: int = Field(default=None, primary_key=True, foreign_key='product.id')
    order: Optional[Order] = Relationship(back_populates='order_items')
    product: Optional[Product] = Relationship(back_populates='stock_quantity')

class UserInDB(Customer):
    hashed_password: str

class TokenData(BaseModel):
    username: str = None
    
class Token(BaseModel):
    access_token: str
    token_type: str

sqlite_file_name = './db.sqlite'
DATABASE_URL = f"sqlite:///{sqlite_file_name}"

app = FastAPI()

tags_metadata = [
    {"name": "Products", "description": "Operations related to products"},
    {"name": "Customers", "description": "Operations related to customers"},
    {"name": "Orders", "description": "Operations related to orders"},
]

engine = create_engine(DATABASE_URL, echo=False)

SQLModel.metadata.create_all(engine)

def authenticate_user(db: Session, username: str, password: str):
    user = db.exec(select(Customer).where(Customer.username == username)).first()
    if user and pwd_context.verify(password, user.password):
        return user
    return None

thread_local = threading.local()

def get_db():
    if not hasattr(thread_local, "session"):
        thread_local.session = Session(engine)
    return thread_local.session

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    user = db.exec(select(Customer).where(Customer.username == username)).first()
    if user:
        return UserInDB(**user.dict(), hashed_password=user.password)

async def get_current_user(db:Session= Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends()
):
    db = get_db()
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get('/products/', response_model=List[Product], tags=['Products'])
async def get_products(skip: int = 0, limit: int = 10, user: UserInDB = Depends(get_current_user), db: Session = Depends(get_db)):
    products = db.exec(select(Product).offset(skip).limit(limit)).all()
    return products

@app.post('/products/', response_model=Product, tags=['Products'])
async def create_product(product: Product, db: Session = Depends(get_db)):
    db.add(product)
    db.commit()
    db.refresh(product)
    return product

@app.get('/products/{product_id}', response_model=Product, tags=['Products'])
async def get_product(product_id: int, db: Session = Depends(get_db)):
    product = db.exec(select(Product).where(Product.id == product_id)).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@app.put('/products/{product_id}', response_model=Product, tags=['Products'])
async def update_product(product_id: int, updated_product: Product, db: Session = Depends(get_db)):
    product = db.exec(select(Product).where(Product.id == product_id)).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    for key, value in updated_product.dict(exclude={"id"}).items():
        setattr(product, key, value)

    db.commit()
    db.refresh(product)
    return product


@app.delete('/products/{product_id}', response_model=Product, tags=['Products'])
async def delete_product(product_id: int, db: Session = Depends(get_db)):
    product = db.exec(select(Product).where(Product.id == product_id)).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    db.delete(product)
    db.commit()
    return product

@app.get('/customers/', response_model=List[Customer], tags=['Customer'])
async def get_customers(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    customers = db.exec(select(Customer).offset(skip).limit(limit)).all()
    return customers

@app.post('/customers/', response_model=Customer, tags=['Customer'])
async def create_customer(customer: Customer, db: Session = Depends(get_db)):
    existing_user = db.exec(select(Customer).where(Customer.username == customer.username)).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")

    hashed_password = pwd_context.hash(customer.password)
    customer_data = customer.dict()
    customer_data["password"] = hashed_password
    db_customer = Customer(**customer_data)
    db.add(db_customer)
    db.commit()
    db.refresh(db_customer)

    access_token = create_access_token(data={"sub": db_customer.id})
    return {"customer": db_customer, "access_token": access_token, "token_type": "bearer"}

@app.get('/customers/{customer_id}', response_model=Customer, tags=['Customer'])
async def get_customer(customer_id: int, db: Session = Depends(get_db)):
    customer = db.exec(select(Customer).where(Customer.id == customer_id)).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer

@app.get('/customers/me', response_model=Customer, tags=['Customer'])
async def get_current_customer(current_user: UserInDB = Depends(get_current_user), db: Session = Depends(get_db)):
    return current_user

@app.post('/orders/', response_model=Order, tags=['Order'])
async def create_order(order: Order, db: Session = Depends(get_db)):
    db.add(order)
    db.commit()
    db.refresh(order)
    return order

@app.get('/customers/{customer_id}/orders/', response_model=List[Order], tags=['Order'])
async def get_customer_orders(customer_id: int, db: Session = Depends(get_db)):
    customer = db.exec(select(Customer).where(Customer.id == customer_id)).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    return customer.orders

@app.get('/orders/{order_id}', response_model=Order, tags=['Order'])
async def get_order(order_id: int, db: Session = Depends(get_db)):
    order = db.exec(select(Order).where(Order.id == order_id)).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order

@app.post('/orders/{order_id}/items/', response_model=OrderItem, tags=['Order'])
async def add_item_to_order(order_id: int, item: OrderItem, db: Session = Depends(get_db)):
    order = db.exec(select(Order).where(Order.id == order_id)).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    total_quantity = sum(item.quantity for item in order.order_items)
    order.total_quantity = total_quantity
    item.order_id = order.id
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@app.get('/orders/{order_id}/items/', response_model=List[OrderItem], tags=['Order'])
async def get_order_items(order_id: int, db: Session = Depends(get_db)):
    order = db.exec(select(Order).where(Order.id == order_id)).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    return order.order_items

@app.put('/orders/{order_id}/items/{item_id}', response_model=OrderItem, tags=['Order'])
async def update_order_item(order_id: int, item_id: int, updated_item: OrderItem, db: Session = Depends(get_db)):
    order = db.exec(select(Order).where(Order.id == order_id)).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    item = db.exec(select(OrderItem).where(OrderItem.id == item_id, OrderItem.order_id == order_id)).first()
    if not item:
        raise HTTPException(status_code=404, detail="Order item not found")

    for key, value in updated_item.dict(exclude={"id", "order_id", "product_id"}).items():
        setattr(item, key, value)

    db.commit()
    db.refresh(item)
    return item

@app.delete('/orders/{order_id}/items/{item_id}', response_model=OrderItem, tags=['Order'])
async def delete_order_item(order_id: int, item_id: int, db: Session = Depends(get_db)):
    order = db.exec(select(Order).where(Order.id == order_id)).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    item = db.exec(select(OrderItem).where(OrderItem.id == item_id, OrderItem.order_id == order_id)).first()
    if not item:
        raise HTTPException(status_code=404, detail="Order item not found")

    db.delete(item)
    db.commit()
    return item
