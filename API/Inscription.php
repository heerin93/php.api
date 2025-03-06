<!-- 
http://domaine/inscription.php : sera interrogée par la méthode =>POST
http://domaine/utilisateurs.php : sera interrogée par la méthode =>GET
http://domaine/compte.php : sera interrogée par la méthode =>GET
http://domaine/modifier-informations.php sera interrogée par la méthode =>PUT
http://domaine/supprimer.php : sera interrogée par la méthode =>DELETE 
-->



<?php
// ! Accès depuis n'importe quel site ou appareil ( * )
header("Access-Control-Allow-Origin: *"); // autres valeurs domain, none

//! Format des données envoyées
header("Content-Type: application/json; charset=UTF-8");

//! Méthode autorisée, ici POST, mais ça peut être GET, PUT ou DELETE
header("Access-Control-Allow-Methods: POST") ;


// Durée de vie de la requête
header("Access-Control-Max-Age: 3600"); //3600 seconde

// Entêtes autorisées
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

//Contrôle de la méthode HTTP
if($_SERVER['REQUEST_METHOD'] != 'POST'){
    //code réponse HTTP
    http_response_code(405);
    //Envoie du message d'erreur
    echo json_encode(["message" => "Methode non autorisée. POST requis.", "code"=>405]);
    //Arrêt du script
    return;
}

//file_get_contents() recupere le contenut d'un fichier
//ex file_get_contents('php://input')
//décoder le JSON  json_decode()

$json = file_get_contents("php://input");

//dechiffre le json

$data =json_decode($json);

//ATTENTION : $data est un objet => il faut accéder aux donnée grâce à la structure objet. Exemple : $data->email
//Maintenant on peut exploiter les données comme on veut
//Par exemple ici, on veut enregistrer un users, grâce à son nickname, son email et son password
//On crée dabord notre alo de anière habituelle comme si on traitait un formulaire
//1)Vérifier les champs vides
if(empty($data->nickname) || empty($data->email) || empty($data->password)) {
    //renvoie un message d'erreur
    http_response_code(400);
    $response = ["message" => "Données manquantes", "code"=> 400];
    echo json_encode($response);
    return;
}
//2) on vérifie le format du mail
if(!filter_var($data->email, FILTER_VALIDATE_EMAIL)){
    //renvoie dun message d'erreur
    http_response_code(400);
    $response = ["message" => "Email pas au bon format", "code"=>400];
    echo json_encode($response);
    return;
}
//3) Nettoyage des données
$nickname = htmlentities(strip_tags(stripslashes(trim($data->nickname))));
$email = htmlentities(strip_tags(stripslashes(trim($data->email))));
$password = htmlentities(strip_tags(stripslashes(trim($data->password))));
//4) hasher le mot de passe
$password = password_hash($password, PASSWORD_BCRYPT);
//5) Vérifier si l'email est disponible ou pas
//5.1 Création de l'objet de connexion
$bdd = new PDO('mysql:host=localhost;dbname=users1',"root","",array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
try {
//5.2 Préparation de la requête SELECT
    $req=$bdd->prepare('SELECT id, nickname, email, psswrd FROM users WHERE email = ?');
//5.3 Binding de PARAM
    $req->bindParam(1, $email, PDO::PARAM_STR);
    //5.4 exécution de la requête
    $req->execute();
    //5.5 Récupération de la réponse de la BDD
    $data = $req->fetchAll(PDO::FETCH_ASSOC);
    //5.6 Vérification si $data est vide
    if (!empty($data)){
        http_response_code(409);
        echo json_encode(["message" => "Email déjà utilisé", "code" => 409]);
        return;
    }

    //6 Enregistrer l'utilisateur
    //6.1 Préparation de la requête INSERT
    $req = $bdd->prepare("INSERT INTO users (nickname, email, psswrd) VALUES (?,?,?)");
    //6.2 Binding de PARAM
    $req->bindParam(1,$nickname,PDO::PARAM_STR);
    $req->bindParam(2, $email, PDO::PARAM_STR);
    $req->bindParam(3, $password, PDO::PARAM_STR);
    $req->execute();

//On peut exploiter les données:
//... 

//Retourner un message 
//encode le code reponse HTTP

    http_response_code(200);

// Tableau associatif de ma réponse
    $tab=['message'=>'Succes!','code'=>200];
//chiffrer la reponse en json
    $json=json_encode($tab);

///affichage du json (ce qui retourne la réponse au client)

    echo $json;

//Arret du script
    return;

} catch(EXCEPTION $error) {
    //Envoyer yne réponse d'erreur 500
    http_response_code(500);
    echo json_encode(["message" => $error->getMessage(), "code" => 500]);
    return;
}
