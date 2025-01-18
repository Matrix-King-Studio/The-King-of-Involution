## 小程序登录
### 需求分析
实现小程序登录：

+ 用户存在---> 直接登录
+ 用户不存在 ---- > 注册流程

### 官方文档
[https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html](https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html)

![](https://cdn.nlark.com/yuque/0/2025/png/40552572/1737177659805-ca926d85-6401-4cda-adfc-6bb25e837baa.png)

### 细化流程
![画板](https://cdn.nlark.com/yuque/0/2025/jpeg/40552572/1737178468614-88c5b447-93c6-4aee-b3ef-aa836edd9f32.jpeg)

### 后端登录代码
在用户表中添加字段

```python
openid = models.CharField(verbose_name="openid", max_length=254, unique=True, null=True, blank=True, db_index=True)
```

视图类

```python
class WXAuthUserView(APIView):
    """
    get:
    根据微信登录的code获取openid
    """
    def get(self, request):
        # 1. 获取前端传入参数
        code = request.query_params.get('code', None)
        if not code:
            return Response(data={"detail": "缺少code"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            data = get_open_id(settings.WX_APPID, settings.WX_APPSECRET, code)
            openid = data.get('openid')
        except Exception as e:
            logger.error(e)
            return Response(data={"detail": "WX服务器异常"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        if not openid:
            return Response(data={"detail": data.get("errmsg", 'WX登录失败')},
                            status=status.HTTP_503_SERVICE_UNAVAILABLE)
        try:
            user = UserModel.objects.get(openid=openid)
        except UserModel.DoesNotExist:
            # 没有绑定用户
            # 需要对openid进行加密
            openid = generate_save_user_token(openid)
            return Response({'openid': openid})
        else:
            # 已经绑定用户
            refresh = RefreshToken.for_user(user)
            # token = {'refresh': str(refresh),
            #          'access': str(refresh.access_token)
            #          }
            return Response({
                'token': str(refresh.access_token),
                # 'real_name': user.real_name,
                'user_id': user.id,
            })
```

工具方法

```python
def get_open_id(appid, secret, js_code):
    # 构建请求url
    url = 'https://api.weixin.qq.com/sns/jscode2session?appid=' + appid + '&secret=' + secret + '&js_code=' + js_code + '&grant_type=authorization_code'
    # 发送请求
    try:
        response = requests.get(url)
        data = response.text
    except:
        raise Exception('wx请求失败')
    # 转化为字典
    try:
        data_dict = json.loads(data)
    except:
        raise Exception('openid获取失败')

    return data_dict


def generate_save_user_token(openid):
    """对openid进行加密"""
    # 1. 创建序列化器对象
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY)
    # 2.调用dumps进行加密
    data = {'openid': openid}
    token = serializer.dumps(data)
    # 3. 返回加密后的openid
    return token


def check_save_user_token(openid):
    """对openid进行解密"""
    # 1. 创建序列化器对象
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY)
    # 2.调用loads进行加密
    # data = {'openid': openid}
    try:
        token = serializer.loads(openid)
        data = serializer.loads(token, max_age=expiration)
    except BadSignature:
        return None
    # 3. 返回解密后的openid
    return token.get('openid')
```

### 后端注册代码
```python
class WXAuthUserView(CreateAPIView):
    """
    get:
    根据微信登录的code获取openid
    """
    serializer_class = WXAuthUserSerializer

    def get(self, request, *args, **kwargs):
        # 1. 获取前端传入参数
        code = request.query_params.get('code', None)
        if not code:
            return Response(data={"detail": "缺少code"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            data = get_open_id(settings.WX_APPID, settings.WX_APPSECRET, code)
            openid = data.get('openid')
        except Exception as e:
            logger.error(e)
            return Response(data={"detail": "WX服务器异常"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        if not openid:
            return Response(data={"detail": data.get("errmsg", 'WX登录失败')},
                            status=status.HTTP_503_SERVICE_UNAVAILABLE)
        try:
            user = UserModel.objects.get(openid=openid)
        except UserModel.DoesNotExist:
            # 没有绑定用户
            # 需要对openid进行加密
            openid = generate_save_user_token(openid)
            return Response({'openid': openid})
        else:
            # 已经绑定用户
            refresh = RefreshToken.for_user(user)
            # token = {'refresh': str(refresh),
            #          'access': str(refresh.access_token)
            #          }
            return Response({
                'token': str(refresh.access_token),
                # 'real_name': user.real_name,
                'user_id': user.id,
            })
```

序列化类

```python
class WXAuthUserSerializer(serializers.ModelSerializer):
    """openid绑定用户的序列化器"""
    phone = serializers.RegexField(r'1[3-9]\d{9}', label='手机号')
    token = serializers.CharField(read_only=True, label='登录态的token')

    class Meta:
        model = UserModel
        fields = (
            'id', 'phone', 'openid',
            'sex', 'token')
        extra_kwargs = {
            'openid': {
                'required': True,
                'write_only': True,
            },
        }

    def validate(self, attrs):
        # 把加密的openid解密
        openid = attrs.get('openid')
        openid = check_save_user_token(openid)
        if openid is None:
            raise serializers.ValidationError('openid无效')
        attrs['openid'] = openid
        phone = attrs.get('phone')
        if UserModel.objects.filter(phone=phone).count() > 0:
            raise serializers.ValidationError('手机号已存在')
        if UserModel.objects.filter(openid=openid).count() > 0:
            raise serializers.ValidationError('该微信已绑定用户')
        return attrs

    def create(self, validated_data):
        validated_data['username'] = str(time.time()) + str(random.randint(1, 9999))
        user = UserModel.objects.create(**validated_data)
        # 生成JWT
        refresh = RefreshToken.for_user(user)
        user.token = str(refresh.access_token)
        return user
```

## 获取手机号
### 官方文档
[https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/getPhoneNumber.html](https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/getPhoneNumber.html)

![](https://cdn.nlark.com/yuque/0/2025/png/40552572/1737181071919-1df8a698-73d5-43d9-8808-21694280dfb3.png)

### 流程图
![画板](https://cdn.nlark.com/yuque/0/2025/jpeg/40552572/1737182106425-88362e97-b16e-4b38-a393-b39f76a519b7.jpeg)



### 代码
```python
class GetPhoneView(APIView):

    def get(self, request):
        cache = caches['access_token']
        # 1. 获取前端传入参数
        code = request.query_params.get('code', None)
        if not code:
            return Response(data={"detail": "缺少code"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # 从缓存中获取access_token
            access_token = cache.get('access_token')
            if access_token is None:
                # 没有获取到access_token,重新获取并存入redis缓存
                data = get_access_token(settings.WX_APPID, settings.WX_APPSECRET)
                access_token = data.get('access_token')
                expires_in = data.get('expires_in')
                if access_token:
                    cache.set('access_token', access_token, expires_in - 10)
                else:
                    logger.error(data)
                    return Response(data={"detail": "WX服务器异常"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
            phone_detail = get_phone_number(code, access_token)
            phone = phone_detail.get('phone_info').get('phoneNumber')
        except Exception as e:
            logger.info(e)
            return Response(data={"detail": "WX服务器异常"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        if not phone:
            return Response(data={"detail": phone_detail.get("errmsg", 'WX登录失败')},
                            status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return Response({
            'phone': phone
        })
```

工具

```python
def get_access_token(appid, secret):
    url = 'https://api.weixin.qq.com/cgi-bin/token?appid=' + appid + '&secret=' + secret + '&grant_type=client_credential'
    # 发送请求
    try:
        response = requests.get(url)
        data = response.text
    except:
        raise Exception('wx请求失败')
    # 转化为字典
    try:
        data_dict = json.loads(data)
    except:
        raise Exception('access_token获取失败')

    return data_dict

def get_phone_number(code, access_token):
    payload = {
        'code': code
        # 'access_token': access_token
    }
    headers = {
        "Content-Type": "application/json;charset=UTF-8"
    }
    url = f'https://api.weixin.qq.com/wxa/business/getuserphonenumber?access_token={access_token}'
    # 发送请求
    try:
        response = requests.post(url, json=payload, headers=headers)
        data = response.text
    except:
        raise Exception('wx请求失败')
    # 转化为字典
    try:
        data_dict = json.loads(data)
    except:
        raise Exception('手机号获取失败')

    return data_dict
```



辅助代码

```python
code_param = openapi.Parameter(name='code', in_=openapi.IN_QUERY, description='wx.login()获取的code',
                                   type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[code_param],
                         operation_description='用户已存在，返回用户数据；用户不存在，返回加密后的openid',
                         operation_summary='微信登录')




code_param = openapi.Parameter(name='code', in_=openapi.IN_QUERY, description='getPhoneNumber获取的code',
                                   type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[code_param],
                         operation_description='根据code获取手机号',
                         operation_summary='获取手机号')



```



