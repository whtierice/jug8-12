from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import bcrypt
import random
import re
import time
import threading
import schedule

# 토큰에서 닉네임을 추출하려면
# from flask_jwt_extended import get_jwt
# claims = get_jwt()
# nickname = claims.get('nickname')

app = Flask(__name__)

# JWT 설정
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False  # TURE일 경우 HTTPS만
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # CSRF 활성화 구문
app.config['JWT_SECRET_KEY'] = '48saj@das90kfhgjgjhgjhgjhgfghydmu645(*p'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

jungle_quiz = [
    {"question": "세탁실에 있는 세탁기의 갯수는?", "answer": "8"},
    {"question": "정글 카페테리아 한끼 식사의 가격은?", "answer": "7000"},
    {"question": "정글 과정에서 사용하는 교과서의 개수는?", "answer": "4"},
    {"question": "운영체제 교과서의 옮긴이는 총 몇명?", "answer": "3"},
    {"question": "숙소동의 층수는?", "answer": "4"},
    {"question": "숙소 비밀번호의 자릿수는?", "answer": "5"},
    {"question": "사용하는 강의실의 호수 중 가장 큰 것은?", "answer": "307"},
    {"question": "반려동물 반입에 관한 벌점은 몇 점?", "answer": "20"},
    {"question": "캠퍼스 내 WIFI의 비밀번호는?", "answer": "junglecampus"}
]

# 공통 함수로 현재 사용자 정보 가져오기
def get_current_user():
    try:
        print("Cookies:", request.cookies)
        current_identity = get_jwt_identity()
        print("JWT Identity:", current_identity)
        if current_identity:
            user = db.cp_users.find_one({'username': current_identity})
            print("User from DB:", user)
            return user
    except Exception as e:
        print(f"Error in get_current_user: {e}")
    return None

# 미인증 사용자 처리
@jwt.unauthorized_loader
def unauthorized_callback(callback):
    # 로그인 페이지로 리다이렉트
    return redirect(url_for('login', message='로그인이 필요합니다.'))

# 토큰 만료 사용자 처리
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    # 쿠키에 토큰이 존재하는 경우에만 메시지를 전달
    if request.cookies.get('access_token_cookie'):
        return redirect(url_for('login', message='로그인 만료입니다. 다시 로그인해주세요.'))
    else:
        return redirect(url_for('login'))


# MongoDB 연결
client = MongoClient('mongodb://test:test@localhost', 27017)
db = client.dbjungle

@app.route('/')
@jwt_required(optional=True)
def home():
 
    page = int(request.args.get('page', 1))
    per_page = 9  
    skip = (page - 1) * per_page

    category_receive = request.args.get('category', '0')
    query = {} if category_receive == "0" else {'category': category_receive}


    total_invites = db.cp_invites.count_documents(query)

    invites = list(db.cp_invites.find(query, {}).sort("created_at", -1).skip(skip).limit(per_page))

    now = datetime.now(timezone.utc) + timedelta(hours=9)
    for invite in invites:
        if 'created_at' in invite:
            if invite['created_at'].tzinfo is None:
                invite['created_at'] = invite['created_at'].replace(tzinfo=timezone.utc)
            diff = now - invite['created_at']
            if diff < timedelta(hours=1):
                if diff < timedelta(minutes=1):
                    invite['created_at'] = "방금"
                else:
                    minutes = int(diff.total_seconds() // 60)
                    invite['created_at'] = f"{minutes}분 전"
            else:
                invite['created_at'] = invite['created_at'].strftime('%Y-%m-%d %H:%M')

    current_user = get_current_user()


    has_more = total_invites > page * per_page

    
    has_previous = page > 1

    return render_template('home.html', invites=invites, user=current_user, page=page, has_more=has_more, has_previous=has_previous)


#초대장 보여주기기
@app.route('/home', methods=['GET'])
@jwt_required(optional=True)
def read_invite():
    page = int(request.args.get('page', 1))
    per_page = 9  
    skip = (page - 1) * per_page
    category_receive = request.args.get('category', '0')
    title_receive = request.args.get('title', '')
    query = {} if category_receive == "0" else {'category': category_receive}
    # 전체 카드 수를 계산 (선택사항, 페이지네이션 버튼 노출에 사용)
    total_invites = db.cp_invites.count_documents(query)
    # 페이지에 해당하는 카드들만 조회
    if category_receive == "0":
        if title_receive == '':
            result = list(db.cp_invites.find({}, {}).sort("created_at", -1).skip(skip).limit(per_page))
        else:
            result = list(db.cp_invites.find({'title': {"$regex": title_receive}}, {}).sort("created_at", -1).skip(skip).limit(per_page))
    else:
        if title_receive == ' ':
            result = list(db.cp_invites.find({'category': category_receive}, {}).sort("created_at", -1).skip(skip).limit(per_page))
        else:
            result = list(db.cp_invites.find({'title': {"$regex": title_receive}, 'category': category_receive}, {}).sort("created_at", -1).skip(skip).limit(per_page))
    now = datetime.now(timezone.utc) + timedelta(hours=9)
    for invite in result:
        if 'created_at' in invite and isinstance(invite['created_at'], datetime):
            if invite['created_at'].tzinfo is None:
                invite['created_at'] = invite['created_at'].replace(tzinfo=timezone.utc)
            diff = now - invite['created_at']
            if diff < timedelta(hours=1):
                if diff < timedelta(minutes=1):
                    invite['created_at'] = "방금"
                else:
                    minutes = int(diff.total_seconds() // 60)
                    invite['created_at'] = f"{minutes}분 전"
            else:
                invite['created_at'] = invite['created_at'].strftime('%Y-%m-%d %H:%M')
    current_user = get_current_user()
    # 다음 페이지, 이전 페이지 여부 계산
    has_more = total_invites > page * per_page
    has_previous = page > 1
    return render_template('home.html', invites=result, user=current_user, page=page, has_more=has_more, has_previous=has_previous)



# 파티 모집 신청
@app.route('/apply', methods=['GET', 'POST'])
@jwt_required()
def apply():
    if request.method == 'POST':
        current_user = get_current_user()
        title_receive = request.form['title_give']
        category_receive = request.form['category_give']
        chat_receive = request.form['chat_give']

        if not title_receive:
            current_user = get_current_user()
            return render_template('apply.html', error_message='제목을 입력해주세요!', user=current_user)
        elif not chat_receive:
            current_user = get_current_user()
            return render_template('apply.html', error_message='오픈 채팅 URL을 입력해주세요!', user=current_user)


        limit_person_receive = request.form['limit_person_give']
        type_receive = request.form['type_give']
        note_receive = request.form['note_give']

        username = current_user['username']
        
        invite = {
            'title': title_receive,
            'limit_person': int(limit_person_receive),
            'now_person': 1,
            'type': type_receive,
            'category': category_receive,
            'chat': chat_receive,
            'note': note_receive,
            'created_by': get_current_user()['username'],
            'participants': [username],  
            "created_at": datetime.now(timezone.utc) + timedelta(hours=9)  
        }


        db.cp_invites.insert_one(invite)
        return redirect(url_for('read_invite', category=0))
    current_user = get_current_user()
    return render_template('apply.html', user=current_user)

# 초대장 삭제 (기본키 이용)
@app.route('/delete', methods=['POST'])
@jwt_required()
def delete():
    current_user = get_current_user()
    id_receive = ObjectId(request.form.get('id_give'))
    invite = db.cp_invites.find_one({'_id': id_receive})
    if invite and current_user and invite.get('created_by') == current_user['username']:
        db.cp_invites.delete_one({'_id': id_receive})
    else:
        return redirect(url_for('read_invite', category=0, error="작성자만 삭제할 수 있습니다."))
    return redirect(url_for('read_invite', category=0, message='삭제 성공!'))


@app.route('/complete', methods=['GET', 'POST'])
@jwt_required()
def complete():
    current_user = get_current_user()  # 현재 로그인한 사용자 정보 가져오기
    if request.method == 'POST':
        id_receive = ObjectId(request.form['id_give'])
        invite = db.cp_invites.find_one({'_id': id_receive})
        # 참여한 사용자가 아직 없다면 처리
        if current_user and current_user['username'] not in invite.get('participants', []):
            result = db.cp_invites.update_one(
                {'_id': id_receive,"now_person": {"$lt": invite['limit_person']}},
                {
                    '$inc': {'now_person': 1},
                    '$push': {'participants': current_user['username']}
                }
            )
            if result.modified_count == 0:
                return redirect(url_for('read_invite', category=0, error="이미 마감된 초대장입니다!"))
        return redirect(url_for('complete', id=str(id_receive)))
    id = ObjectId(request.args.get('id'))
    result = db.cp_invites.find_one({'_id': id}, {'_id': 0})
    result['created_at'] = result['created_at'].strftime('%Y-%m-%d %H:%M')
    current_user = get_current_user()
    return render_template('complete.html', invite=result, user=current_user)

# 업데이트 페이지 (GET)와 업데이트 처리 (POST)
@app.route('/update', methods=['GET', 'POST'])
@jwt_required()
def update():
    current_user = get_current_user()
    if request.method == 'POST':
        id_receive = ObjectId(request.form['id_give'])
        title_receive = request.form['title_give']
        category_receive = request.form['category_give']
        chat_receive = request.form['chat_give']
       

        if not title_receive:
            return render_template('update.html', error_message='제목을 입력해주세요!', user=current_user)
        elif not chat_receive:
            return render_template('update.html', error_message='오픈 채팅 URL을 입력해주세요!', user=current_user)
        
        limit_person_receive = request.form['limit_person_give']
        type_receive = request.form['type_give']
        note_receive = request.form['note_give']
        updated_data = {
            'title': title_receive,
            'limit_person': int(limit_person_receive),
            'type': type_receive,
            'category': category_receive,
            'chat': chat_receive,
            'note': note_receive,
            "created_at": datetime.now(timezone.utc) + timedelta(hours=9),
        }
        db.cp_invites.update_one({'_id': id_receive}, {'$set': updated_data})
        return redirect(url_for('read_invite', category=0, user=current_user))
    
    id_receive = ObjectId(request.args.get('id'))
    invite = db.cp_invites.find_one({'_id': id_receive})
    if invite and current_user and invite.get('created_by') ==          current_user['username']:
        result = db.cp_invites.find_one({'_id': id_receive})
    else:
        return redirect(url_for('read_invite', category=0, error="작성자만 수정할 수 있습니다."))
     
    return render_template('update.html', invite=result, user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = db.cp_users.find_one({'username': username})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            # JWT 액세스 토큰 생성, 닉네임 추가
            access_token = create_access_token(identity=username, additional_claims={'nickname': user['nickname']})

            next_page = request.args.get('next')
            if next_page:
                resp = redirect(next_page)
            else:
                resp = redirect(url_for('home'))

            resp.set_cookie('access_token_cookie', access_token, httponly=True, path='/')
            return resp
        else:
            current_user = get_current_user()
            return render_template('login.html', error_message='아이디 또는 비밀번호가 일치하지 않습니다!', user=current_user)

    message = request.args.get('message', '')
    current_user = get_current_user()
    next_page = request.args.get('next', '')
    return render_template('login.html', message=message, user=current_user, next=next_page)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        random_quiz = random.choice(jungle_quiz)
        random_index = jungle_quiz.index(random_quiz)
        username = request.form.get('username')
        password = request.form.get('password')
        nickname = request.form.get('nickname')
        quiz_answer = request.form.get('quiz_answer')
        quiz_index = int(request.form.get('quiz_index', 0))

        if not username or not password or not nickname:
            current_user = get_current_user()
            return render_template('signup.html', error_message='모든 필드를 입력해주세요!', quiz=random_quiz, quiz_index=random_index, user=current_user)

        if len(password) < 6:
            current_user = get_current_user()
            return render_template('signup.html', error_message='비밀번호는 최소 6자 이상이어야 합니다!', quiz=random_quiz, quiz_index=random_index, user=current_user)

        existing_nickname = db.cp_users.find_one({'nickname': nickname})
        if existing_nickname:
            current_user = get_current_user()
            return render_template('signup.html', error_message='이미 사용 중인 닉네임입니다!', quiz=random_quiz, quiz_index=random_index, user=current_user)

        correct_answer = str(jungle_quiz[quiz_index]["answer"]).strip()
        user_answer = quiz_answer.strip()

        if user_answer != correct_answer:
            random_quiz = random.choice(jungle_quiz)
            random_index = jungle_quiz.index(random_quiz)
            current_user = get_current_user()
            return render_template('signup.html', error_message='정글 퀴즈 정답이 틀렸습니다!', 
                                   quiz=random_quiz, quiz_index=random_index, user=current_user)

        existing_user = db.cp_users.find_one({'username': username})
        if existing_user:
            random_quiz = random.choice(jungle_quiz)
            random_index = jungle_quiz.index(random_quiz)
            current_user = get_current_user()
            return render_template('signup.html', error_message='이미 존재하는 아이디입니다!', 
                                   quiz=random_quiz, quiz_index=random_index, user=current_user)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = {
            'username': username,
            'password': hashed_password,
            'nickname': nickname,
        }
        db.cp_users.insert_one(user)

        return redirect(url_for('login', message='회원가입 성공! 로그인해주세요.'))

    random_quiz = random.choice(jungle_quiz)
    random_index = jungle_quiz.index(random_quiz)
    current_user = get_current_user()
    return render_template('signup.html', quiz=random_quiz, quiz_index=random_index, user=current_user)

@app.route('/api/check-username', methods=['POST'])
def check_username():
    username = request.form.get('username')

    if not username:
        return jsonify({'success': False, 'message': '아이디를 입력해주세요.'})

    if not re.match("^[A-Za-z0-9]+$", username):
        return jsonify({'success': False, 'message': '아이디는 영어와 숫자만 사용 가능합니다.'})

    existing_user = db.cp_users.find_one({'username': username})

    if existing_user:
        return jsonify({'success': False, 'message': '이미 사용 중인 아이디입니다.'})
    else:
        return jsonify({'success': True, 'message': '사용 가능한 아이디입니다.'})

@app.route('/api/check-nickname', methods=['POST'])
def check_nickname():
    nickname = request.form.get('nickname')

    if not nickname:
        return jsonify({'success': False, 'message': '닉네임을 입력해주세요.'})

    existing_nickname = db.cp_users.find_one({'nickname': nickname})

    if existing_nickname:
        return jsonify({'success': False, 'message': '이미 사용 중인 닉네임입니다.'})
    else:
        return jsonify({'success': True, 'message': '사용 가능한 닉네임입니다.'})

@app.route('/api/check-quiz-answer', methods=['POST'])
def check_quiz_answer():
    quiz_index = int(request.form.get('quiz_index', 0))
    quiz_answer = request.form.get('quiz_answer', '')

    if not quiz_answer:
        return jsonify({'success': False, 'message': '퀴즈 답변을 입력해주세요.'})

    correct_answer = str(jungle_quiz[quiz_index]["answer"]).strip()
    user_answer = quiz_answer.strip()

    if user_answer != correct_answer:
        return jsonify({'success': False, 'message': '정글 퀴즈 정답이 틀렸습니다!'})
    else:
        return jsonify({'success': True, 'message': '정답입니다!'})

@app.route('/logout', methods=['GET'])
def logout():
    resp = redirect(url_for('login'))
    resp.delete_cookie('access_token_cookie', path='/')
    return resp

@app.route('/check-jwt')
@jwt_required()
def check_jwt():
    print("Cookies:", request.cookies)
    try:
        identity = get_jwt_identity()
        print("Identity:", identity)
        if identity:
            user = db.cp_users.find_one({'username': identity})
            return jsonify({"logged_in": True, "username": identity, "user": str(user)})
        return jsonify({"logged_in": False})
    except Exception as e:
        return jsonify({"error": str(e)})

# 마감 데이터 삭제
def reset_db():
    result = list(db.cp_invites.find({}, {}))
    for invite in result:
        if invite.get("limit_person") == invite.get("now_person"):
            db.cp_invites.delete_one({"_id": ObjectId(invite["_id"])})
            print(f"[{datetime.now()}] 삭제된 문서: {invite['_id']}")
    print(f"[{datetime.now()}] DB 초기화 완료!")

# :작은_파란색_다이아몬드: 스케줄 등록 (매일 새벽 4시 실행)
schedule.every().day.at("04:00").do(reset_db)
def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)
def start_scheduler():
    thread = threading.Thread(target=run_scheduler, daemon=True)
    thread.start()

start_scheduler()

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
