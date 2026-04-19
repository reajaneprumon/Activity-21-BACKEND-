<?php
require __DIR__ . '/../vendor/autoload.php';

use Slim\Factory\AppFactory;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$secret_key = "FGDFKREIOUTGOEUGEDLFBNcbgvdfupgibvot63482";

$authMiddleware = function ($request, $handler) use ($secret_key) {
    $authHeader = $request->getHeaderLine('Authorization');

    if (!$authHeader) {
        $response = new Slim\Psr7\Response();
        $response->getBody()->write(json_encode(["error"=>"Token required"]));
        return $response->withHeader('Content-Type','application/json');
    }

    $token = str_replace("Bearer ", "", $authHeader);

    try {
        JWT::decode($token, new Key($secret_key, 'HS256'));
    } catch (Exception $e) {
        $response = new Slim\Psr7\Response();
        $response->getBody()->write(json_encode(["error"=>"Invalid token"]));
        return $response->withHeader('Content-Type','application/json');
    }

    return $handler->handle($request);
};


$app = AppFactory::create();
$app->addBodyParsingMiddleware();

// DATABASE CONNECTION
$pdo = new PDO("mysql:host=localhost;dbname=activity21_slimphp", "root", "");
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// ================= REGISTER =================
$app->post('/register', function ($req, $res) use ($pdo) {
    $data = $req->getParsedBody();

    $password = password_hash($data['password'], PASSWORD_BCRYPT);
    $token = bin2hex(random_bytes(16));

    $stmt = $pdo->prepare("INSERT INTO users (name,email,password,verification_token) VALUES (?,?,?,?)");
    $stmt->execute([$data['name'], $data['email'], $password, $token]);

    // SEND EMAIL
    $mail = new PHPMailer(true);

    try {
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = 'prumonreajane@gmail.com';
        $mail->Password = 'jiwbidxsvsrqvvyq';
        $mail->SMTPSecure = 'tls';
        $mail->Port = 587;

        $mail->setFrom('your_email@gmail.com', 'Activity21');
        $mail->addAddress($data['email']);

        $link = "http://localhost:8000/verify?token=$token";

        $mail->isHTML(true);
        $mail->Subject = 'Verify Account';
        $mail->Body = "Click here to verify: <a href='$link'>$link</a>";

        $mail->send();
    } catch (Exception $e) {
        // optional error
    }

    $res->getBody()->write(json_encode(["message"=>"Registered. Check email."]));
    return $res->withHeader('Content-Type', 'application/json');
});

$app->get('/verify', function ($req, $res) use ($pdo) {
    $token = $_GET['token'];

    $stmt = $pdo->prepare("UPDATE users SET is_verified=1 WHERE verification_token=?");
    $stmt->execute([$token]);

    $res->getBody()->write("Account verified! You can now login.");
    return $res;
});

// ================= LOGIN =================
$app->post('/login', function ($req, $res) use ($pdo, $secret_key) {
    $data = $req->getParsedBody();

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email=?");
    $stmt->execute([$data['email']]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($data['password'], $user['password'])) {
        $res->getBody()->write(json_encode(["error"=>"Invalid login"]));
        return $res->withHeader('Content-Type', 'application/json');
    }

	if ($user['is_verified'] == 0) {
		$res->getBody()->write(json_encode(["error"=>"Please verify your email first"]));
		return $res->withHeader('Content-Type', 'application/json');
	}

    // CREATE TOKEN
    $payload = [
        "user_id" => $user['id'],
        "email" => $user['email'],
        "exp" => time() + 3600
    ];

    $jwt = JWT::encode($payload, $secret_key, 'HS256');

    $res->getBody()->write(json_encode([
        "message"=>"Login success",
        "token"=>$jwt
    ]));

    return $res->withHeader('Content-Type', 'application/json');
});

/* ===============================
   UPDATE PROFILE
================================= */
$app->post('/profile', function ($req, $res) use ($pdo, $secret_key) {

    $authHeader = $req->getHeaderLine('Authorization');
    $token = str_replace("Bearer ", "", $authHeader);

    try {

        $decoded = JWT::decode(
            $token,
            new Key($secret_key, 'HS256')
        );

        $user_id = $decoded->user_id;

    } catch (\Throwable $e) {

        $res->getBody()->write(json_encode([
            "error" => "Invalid token"
        ]));

        return $res->withStatus(401)
                   ->withHeader('Content-Type', 'application/json');
    }

    $data = $req->getParsedBody();
    $uploadedFiles = $req->getUploadedFiles();

    $filename = null;

    if (isset($uploadedFiles['image'])) {

        $image = $uploadedFiles['image'];

        if ($image->getError() === UPLOAD_ERR_OK) {

            $filename = time() . "_" . $image->getClientFilename();

            $uploadPath = __DIR__ . '/uploads/';

            if (!is_dir($uploadPath)) {
                mkdir($uploadPath, 0777, true);
            }

            $image->moveTo($uploadPath . $filename);
        }
    }

    if ($filename) {

        $stmt = $pdo->prepare("
            UPDATE users
            SET name=?, image=?
            WHERE id=?
        ");

        $stmt->execute([
            $data['name'],
            $filename,
            $user_id
        ]);

    } else {

        $stmt = $pdo->prepare("
            UPDATE users
            SET name=?
            WHERE id=?
        ");

        $stmt->execute([
            $data['name'],
            $user_id
        ]);
    }

    $res->getBody()->write(json_encode([
        "message" => "Profile updated"
    ]));

    return $res->withHeader('Content-Type', 'application/json');

})->add($authMiddleware);

/* ===============================
   GET PROFILE
================================= */
$app->get('/profile', function ($req, $res) use ($pdo, $secret_key) {

    $authHeader = $req->getHeaderLine('Authorization');

    $token = str_replace("Bearer ", "", $authHeader);

    try {

        $decoded = JWT::decode(
            $token,
            new Key($secret_key, 'HS256')
        );

        $user_id = $decoded->user_id;

        $stmt = $pdo->prepare("
            SELECT id, name, email, image
            FROM users
            WHERE id=?
        ");

        $stmt->execute([$user_id]);

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        $res->getBody()->write(json_encode($user));

        return $res->withHeader(
            'Content-Type',
            'application/json'
        );

    } catch (\Throwable $e) {

        $res->getBody()->write(json_encode([
            "error" => "Invalid token"
        ]));

        return $res
            ->withStatus(401)
            ->withHeader(
                'Content-Type',
                'application/json'
            );
    }

})->add($authMiddleware);

$app->post('/forgot-password', function ($req, $res) use ($pdo) {
    $data = $req->getParsedBody();

    $token = bin2hex(random_bytes(16));

    $stmt = $pdo->prepare("UPDATE users SET reset_token=? WHERE email=?");
    $stmt->execute([$token, $data['email']]);

    // SEND EMAIL
    $mail = new PHPMailer(true);

    try {
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = 'prumonreajane@gmail.com';
        $mail->Password = 'jiwbidxsvsrqvvyq';
        $mail->SMTPSecure = 'tls';
        $mail->Port = 587;

        $mail->setFrom('your_email@gmail.com', 'Activity21');
        $mail->addAddress($data['email']);

        $link = "http://127.0.0.1:5500/reset.html?token=$token";
        
        $mail->isHTML(true);
        $mail->Subject = 'Reset Password';
        $mail->Body = "Click here to reset your password: <a href='$link'>$link</a>";

        $mail->send();
    } catch (Exception $e) {}

    $res->getBody()->write(json_encode(["message"=>"Reset link sent"]));
    return $res->withHeader('Content-Type', 'application/json');
});

$app->post('/reset-password', function ($req, $res) use ($pdo) {
    $data = $req->getParsedBody();

    $password = password_hash($data['password'], PASSWORD_BCRYPT);

    $stmt = $pdo->prepare("UPDATE users SET password=?, reset_token=NULL WHERE reset_token=?");
    $stmt->execute([$password, $data['token']]);

    $res->getBody()->write(json_encode(["message"=>"Password updated"]));
    return $res->withHeader('Content-Type', 'application/json');
});


// ================= CREATE ITEM =================
$app->post('/items', function ($req, $res) use ($pdo) {

    $uploadedFiles = $req->getUploadedFiles();

    if (isset($uploadedFiles['image'])) {
        $image = $uploadedFiles['image'];
        $filename = time() . "_" . $image->getClientFilename();

        $image->moveTo(__DIR__ . '/uploads/' . $filename);
    } else {
        $filename = null;
    }

    $data = $req->getParsedBody();

    $stmt = $pdo->prepare("INSERT INTO items (name,description,image) VALUES (?,?,?)");
    $stmt->execute([$data['name'], $data['description'], $filename]);

    $res->getBody()->write(json_encode(["message"=>"Item added"]));
    return $res->withHeader('Content-Type', 'application/json');

})->add($authMiddleware);


$app->get('/items', function ($req, $res) use ($pdo) {
    $stmt = $pdo->query("SELECT * FROM items");
    $data = $stmt->fetchAll();

    $res->getBody()->write(json_encode($data));
    return $res->withHeader('Content-Type', 'application/json');
})->add($authMiddleware);

/* ===============================
   UPDATE ITEM
================================= */
$app->post('/items/{id}', function ($req, $res, $args) use ($pdo) {

    $id = $args['id'];

    $uploadedFiles = $req->getUploadedFiles();
    $data = $req->getParsedBody();

    $filename = null;

    // upload new image if selected
    if (isset($uploadedFiles['image'])) {

        $image = $uploadedFiles['image'];

        if ($image->getError() === UPLOAD_ERR_OK) {

            $filename = time() . "_" . $image->getClientFilename();

            $uploadPath = __DIR__ . '/uploads/';

            if (!is_dir($uploadPath)) {
                mkdir($uploadPath, 0777, true);
            }

            $image->moveTo($uploadPath . $filename);
        }
    }

    // if no new image, update text only
    if ($filename) {

        $stmt = $pdo->prepare("
            UPDATE items
            SET name=?, description=?, image=?
            WHERE id=?
        ");

        $stmt->execute([
            $data['name'],
            $data['description'],
            $filename,
            $id
        ]);

    } else {

        $stmt = $pdo->prepare("
            UPDATE items
            SET name=?, description=?
            WHERE id=?
        ");

        $stmt->execute([
            $data['name'],
            $data['description'],
            $id
        ]);
    }

    $res->getBody()->write(json_encode([
        "message" => "Item updated"
    ]));

    return $res->withHeader('Content-Type', 'application/json');

})->add($authMiddleware);



/* ===============================
   DELETE ITEM
================================= */
$app->delete('/items/{id}', function ($req, $res, $args) use ($pdo) {

    $id = $args['id'];

    // get image first
    $stmt = $pdo->prepare("SELECT image FROM items WHERE id=?");
    $stmt->execute([$id]);
    $item = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($item) {

        if (!empty($item['image'])) {

            $file = __DIR__ . '/uploads/' . $item['image'];

            if (file_exists($file)) {
                unlink($file);
            }
        }

        $stmt = $pdo->prepare("DELETE FROM items WHERE id=?");
        $stmt->execute([$id]);
    }

    $res->getBody()->write(json_encode([
        "message" => "Item deleted"
    ]));

    return $res->withHeader('Content-Type', 'application/json');

})->add($authMiddleware);



$app->add(function ($request, $handler) {

    if ($request->getMethod() === 'OPTIONS') {
        $response = new Slim\Psr7\Response();
    } else {
        $response = $handler->handle($request);
    }

    return $response
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
});

$app->run();