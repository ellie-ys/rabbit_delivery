import os
from admin import db_password

BASE_DIR = os.path.dirname(__file__) 
# 폴더 구조가 달라져도, 현재 폴더를 가져와서 사용할 수 있도록 설정합니다.

#rabbit.db
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:'+db_password+'@localhost:3306/rabbit?charset=utf8'

SQLALCHEMY_TRACK_MODIFICATIONS = False
# 메모리사용량

