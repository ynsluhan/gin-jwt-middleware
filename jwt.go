package gin_middlewares

import (
	"context"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"log"
	RedisPool "github.com/ynsluhan/go-redis-pool"
	"github.com/ynsluhan/go-r"
	config "github.com/ynsluhan/go-config"
	"time"
)

var conf *config.Config

func init() {
	conf = config.GetConf()
}

var ctx = context.Background()

/**
 * @Author yNsLuHan
 * @Description: gin jwt
 * @return Config
 */
func Jwt() gin.HandlerFunc {
	// init 获取rdb
	// 每次请求都进行处理
	return func(c *gin.Context) {
		// 获取token
		token := c.Request.Header.Get("Authorization")
		// 判断token
		if token == "" {
			R.R(c, 0, "认证失败,未携带token", nil)
			c.Abort()
			return
		}
		// 分离token, 含有Bearer 清开启
		//token = strings.Split(token, " ")[1]
		j := NewJWT()
		// 对token进行解析
		claims, err := j.ParseToken(token)
		// 判断解析是否出错
		if err != nil {
			if err == TokenExpired {
				R.R(c, 0, "认证失败,认证过期", nil)
				c.Abort()
				return
			}
			R.R(c, 0, err.Error(), nil)
			c.Abort()
			return
		}
		// 验证通过后，将token解析后的user信息交由下一个路由处理,并将解析出的信息传递下去
		c.Set("claims", claims)
		// 使用redis token进行验证
		if conf.Server.EnableRedisJwt {
			result, err := RedisPool.GetSentinelMaster().Get(ctx, claims.Openid).Result()
			if err != nil {
				log.Print(err)
				return
			}
			if result != token {
				c.Abort()
				R.R(c, 0, "token 过期", nil)
			}
		}
		c.Next()
	}
}

// 一些常量
var (
	// token错误信息的定义
	// 是否过期的token err
	TokenExpired error = errors.New("Token is expired")
	// 是否为激活的token
	TokenNotValidYet error = errors.New("Token not active yet")
	// 是否是正确格式的token
	TokenMalformed error = errors.New("That's not even a token")
	// 是否有效的token
	TokenInvalid error = errors.New("Couldn't handle this token:")
	// 签名信息
	SignKey string = "ynsluhanUUwebUUapi"
)

// 载荷，可以加一些自己需要的信息
// 用户token中科院提取用户信息之类
type CustomClaims struct {
	ID       int    `json:"userId"`
	Mobile   string `json:"mobile"`
	Avatar   string `json:"avatar"`
	NickName string `json:"nickname"`
	Openid   string `json:"openid"`
	jwt.StandardClaims
}

// 新建一个jwt实例
func NewJWT() *JWT {
	return &JWT{
		[]byte(GetSignKey()),
	}
}

// 获取signKey
func GetSignKey() string {
	return SignKey
}

// 这是SignKey
// 修改全局变量的签名信息，用于token签名
func SetSignKey(key string) string {
	SignKey = key
	return SignKey
}

// JWT 签名结构
type JWT struct {
	SigningKey []byte
}

// CreateToken 生成一个token
// 参数为一个user对象
// 返回参数：
// token, err
func (j *JWT) CreateToken(claims CustomClaims) (string, error) {
	// 生成token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// 返回token,err
	return token.SignedString(j.SigningKey)
}

// 解析token
// 参数为：token
// 返回两个结果，
// 第一个为一个对象，第二个为err错误信息
func (j *JWT) ParseToken(tokenString string) (*CustomClaims, error) {
	// 解析token，  传入token，传入空的user结构体，
	var c CustomClaims
	token, err := jwt.ParseWithClaims(tokenString, &c, func(token *jwt.Token) (interface{}, error) {
		return j.SigningKey, nil
	})
	// 判断err
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			// 判断token是否正确格式
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, TokenMalformed
				// 判断token是否过期
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				// Token is expired
				return nil, TokenExpired
				// 是否激活
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, TokenNotValidYet
				// 是否为有效
			} else {
				return nil, TokenInvalid
			}
		}
	}
	// 校验通过，返回user对象
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	// 校验不通过，返回无效token信息
	return nil, TokenInvalid
}

// 更新token
// 参数为token
// 返回结果：
// token, err
func (j *JWT) RefreshToken(tokenString string) (string, error) {
	jwt.TimeFunc = func() time.Time {
		return time.Unix(0, 0)
	}
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.SigningKey, nil
	})
	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		jwt.TimeFunc = time.Now
		claims.StandardClaims.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
		return j.CreateToken(*claims)
	}
	return "", TokenInvalid
}
