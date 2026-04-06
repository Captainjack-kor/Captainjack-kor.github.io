
# 목차
- [[CVE-2023-40031#개요|개요]]
- [[CVE-2023-40031#분석|분석]]
- [[CVE-2023-40031#PoC|PoC]]
- Expoloit 가능 여부
-  [[CVE-2023-40031#Ref|Ref]]

# 개요

프리 소스 코드 에디터 Notepad++에서 조작된 파일을 열 때 발생함


# 분석

취약한 버전의 소스코드(https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.5.2)를 다운받아 취약한 부분을 분석함

Notepad++는 소스코드를 깃 저장소에서 오픈소스로 공유하고 있어 취약한 버전의 차이를 확인 해 볼 수 있었음

![[Pasted image 20260113004609.png]]

깃의 소스 컴페어를 통해 buffer overflow 난 부분을 확인 가능함

해당함수는 `Utf8_16_Read::convert` 함수로 입력받은 버퍼(`buf`)의 내용을 인자로 전달받은 인코딩(`m_eEncoding`)에 맞춰 변환하고, 변환된 데이터를 가리키는 포인터와 그 크기를 반환하는 함수임

기본적으로 파일을 읽을 때 맨 처음 아래의 로직에 접근하게 됨 
특별한거 없이 초기 값을 설정해주고 detmineEncoding() 함수를 호출하여 파일의 타입을 설정함

```cpp
static	size_t nSkip = 0;
	m_pBuf = (ubyte*)buf;
	m_nLen = len;
	m_nNewBufSize = 0;
	
if (m_bFirstRead == true)
    {
		determineEncoding(); // 이쪽 함수를 통해 인코딩 확인 
		nSkip = m_nSkip; // 건너뛸 바이트 수를 이쪽에서 설정
		m_bFirstRead = false;
	}

```

determineEncoding함수를 통해 m_nSkip의 초기값을설정해주게 됨
읽는 파일의 BOM에 따라 인코딩 방식을 확인하고 정해진 BOM 크기에 따라 m_nSkip이 결정 짓게 됨

※ 여기서 BOM은 파일을 읽을 때 파일의 타입을 결정 짓는 부분으로 파일의 맨 앞에 값으로 지정 됨 -> 만약 파일의 가장 앞 부분이 b'\xfe\xff'로 되어있다면 해당 파일을 UTF-16BE로 판단하여 설정 함

```cpp
void Utf8_16_Read::determineEncoding()
{
	INT uniTest = IS_TEXT_UNICODE_STATISTICS;
	m_eEncoding = uni8Bit;
	m_nSkip = 0;

    // detect UTF-16 big-endian with BOM
	if (m_nLen > 1 && m_pBuf[0] == k_Boms[uni16BE][0] && m_pBuf[1] == k_Boms[uni16BE][1])
	{
		m_eEncoding = uni16BE;
		m_nSkip = 2;
	}
    // detect UTF-16 little-endian with BOM
	else if (m_nLen > 1 && m_pBuf[0] == k_Boms[uni16LE][0] && m_pBuf[1] == k_Boms[uni16LE][1])
	{
		m_eEncoding = uni16LE;
		m_nSkip = 2;
	}
    // detect UTF-8 with BOM
	else if (m_nLen > 2 && m_pBuf[0] == k_Boms[uniUTF8][0] && 
		m_pBuf[1] == k_Boms[uniUTF8][1] && m_pBuf[2] == k_Boms[uniUTF8][2])
	{
		m_eEncoding = uniUTF8;
		m_nSkip = 3;
	}
	...
}
```

다시 `Utf8_16_Read::convert`로 돌아가 타입을 조금 나눠서 확인해보면 먼저 조건에 걸리는 7Bit, 8Bit, Cookie 인코딩의 경우에는 주석에서도 알 수 있듯이 별도의 변환 없이 원본 데이터를 그대로 사용함

```cpp
switch (m_eEncoding)
{
	case uni7Bit:
    case uni8Bit:
    case uniCookie: {
        // Do nothing, pass through
		m_nAllocatedBufSize = 0;
        m_pNewBuf = m_pBuf;
		m_nNewBufSize = len;
        break;
    }
```

다음 부분은 UTF-8 인코딩이며 해당 인코딩은 파일 시작 부분의 BOM 크기만큼 건너뛰고 그 다음부터를 사용함

```cpp
 case uniUTF8: {
     // Pass through after BOM
	 m_nAllocatedBufSize = 0;
     m_pNewBuf = m_pBuf + nSkip; 
	 m_nNewBufSize = len - nSkip;
     break;
 }    
```

그 다음 부분인 UTF-16의 경우 변환  후 최대 버퍼 사이즈인(newSize) 변수를 설정 해주고 있는데, 여기서 설정 되는 사이즈가 조금 눈여겨볼 포인트임

```cpp
case uni16BE_NoBOM:
case uni16LE_NoBOM:
case uni16BE:
case uni16LE: {
    size_t newSize = len + len / 2 + 1;  // 취약점 발생 부분
    
	if (m_nAllocatedBufSize != newSize)
    {
		if (m_pNewBuf)
			delete [] m_pNewBuf;
        m_pNewBuf  = NULL;
        m_pNewBuf  = new ubyte[newSize];
		m_nAllocatedBufSize = newSize;
    }
    
    ubyte* pCur = m_pNewBuf;
    
    m_Iter16.set(m_pBuf + nSkip, len - nSkip, m_eEncoding);

	while (m_Iter16)
	{
		++m_Iter16;
		utf8 c;
		while (m_Iter16.get(&c))
			*pCur++ = c;
	}
	m_nNewBufSize = pCur - m_pNewBuf;

    break;
}
default:
    break;
```


개발자는 저상적인 UTF-16 데이터를 UTF-8을 변환할 때 최대 1.5배가 넘지 않겠다고 가정하고 위와 같은 식을 설정하였음

한글로 예를 들면 '강'이라는 글자는 UTF-16에서 UTF-8로 변환 될 때 1.5배가 늘어남

- UTF-16 : `\xac\15` `(2바이트)`
- UTF-8: `\xed\x95\x9c` `(3바이트)`

즉 최대 1.5배가 늘어나는 설정 정상적인 프로세스에서는 딱 맞는 설정임

숫자로 예를들면 10이라는 길이로 newSize를 설정한다면
`newSize = 10 + 10 / 2 + 1`로 16이라는 값이 설정 되어 안전함
2라는 길이로 설정하더라도
`newSize = 2 + 2 / 2 + 1`로 4바이트가 되어 안전하게 됨

이 +1을 우회하기 위해서는 몇가지 트릭이 존재하는데(서로게이트 페어, 홀수 바이트 공격, 0xffff 경계값 반복.. 등등) 이번에는 잘못된 데이터를 삽입하여 오버플로우를 발생 시키는 경우에 대해 확인 해 보기로함

먼저 입력 값으로 `\xff\xff`를 준다고 가정하면, 마지막 끝에 `\xff`만 남을 시 covert는 유효한 데이터가 아니라서 표준 에러 문자로 반환을 시도하게 됨

다시 정리하자면

1.  입력 데이터는 아래와 같이 1.5배가 늘어남
- 입력 : \xff\xff (2바이트)
- 출력 : \ef\xbf\xbd (3바이트)

1. 파일의 마지막 `\xff` (1바이트)가 남아 에러를 출력 (왜? UTF-16은 2바이트씩 짝을 지어 읽게 되는데 파일의 마지막에 `\xff` 1바이트만 남게 되면, 변환기는 매칭 되는 짝이 없어 마지막 에러를 뱉어냄)

이 마지막 1바이트 찌꺼기가 변환기를 거쳐 3바이트 에러 문자로 변하는 순간
`newSize = len + len/2 + 1`에서 준 +1 공간마저 초과 됨

# PoC

이제 공개 된 POC를 보자

```cpp
with open("poc", "wb") as f:
  f.write(b'\xfe\xff')
  f.write(b'\xff' * (128 * 1024 + 4 - 2 + 1))
```

첫 디코딩 데이터를 UTF-16 변환으로 강제하기 위해 값을 `\xfe\xff`로 해주어, 취약한 newSize 부분으로 접근하도록 설정해주고, `\xff`를 이용하여 버퍼오버 플로우를 발생 시키는 것을 볼 수 있다.

여기서 `128 * 1024`로 파일크기를 읽는 부분을 설정해준 이유는 파일을 읽을 때 보통 128KB 씩 파일을 끊어 읽기 때문에 이 기본 작업 단위인 128KB를 꽉 채우기 위해 설정한 값이다.

뒤에 오는 `+4`는 앞서 오는 BOM(`\xfe\xff`) 2바이트를 변환 대상에서 제외되기 때문에 실제 len 사이즈에서 2를 빼주게 된다.

```
m_Iter16.set(m_pBuf + nSkip, len - nSkip, m_eEncoding);
```

마지막 `+1` 전체 크기를 홀수로 만들어 앞서 기술한 UTF-16 특성을 활용하여 `\xff` (1바이트)가 남도록 유도하는 과정이다.

# 조치

해당 UTF-16 변환 부분은 입력 값을 더 넉넉한 버퍼를 할당 받을 수 있게 변경 됨

```cpp
size_t newSize = (len + len % 2) + (len + len % 2) / 2;
```


# Ref

https://securitylab.github.com/advisories/GHSL-2023-092_Notepad__/

