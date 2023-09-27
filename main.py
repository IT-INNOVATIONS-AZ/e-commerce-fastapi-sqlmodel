from fastapi import Depends, FastAPI, HTTPException
from sqlmodel import Field, SQLModel, Session, create_engine, Relationship, select
from typing import List, Optional
from datetime import datetime

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
    customer_id: Optional[int] = Field(default=None, foreign_key="customer.id", primary_key=True)
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

sqlite_file_name = './db.sqlite'
DATABASE_URL = f"sqlite:///{sqlite_file_name}"

app = FastAPI()

tags_metadata = [
    {"name": "Products", "description": "Operations related to products"},
    {"name": "Customers", "description": "Operations related to customers"},
    {"name": "Orders", "description": "Operations related to orders"},
]

engine = create_engine(DATABASE_URL, echo=True)

SQLModel.metadata.create_all(engine)

def get_db():
    with Session(engine) as db:
        yield db

@app.get('/products/', response_model=List[Product], tags=['Products'])
async def get_products(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
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
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer

@app.get('/customers/{customer_id}', response_model=Customer, tags=['Customer'])
async def get_customer(customer_id: int, db: Session = Depends(get_db)):
    customer = db.exec(select(Customer).where(Customer.id == customer_id)).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer

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