import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher

const val ALGORITHM = "RSA"

fun main() {

    do {
        var option = menu();

        var keys = generateKeys();
        val publicMia = keys.first
        val private = keys.second

        if (option == 1) { // ENCRYPTAR
            print("Escribe la clave publica del otro Usuario para mandarle el mensage: ")
            var publicaUsuario = readln()
            var message = AskForMessage()
            var palabraEncriptada = encrypt(message, publicaUsuario);
            println(palabraEncriptada)


        } else if (option == 2) {
            println("TU CLAVE PUBLICA ES: ${publicMia}")
            print("Escribe el mensaje cifrado: ")
            var mensajeEncriptado = readln();
            var palabraDesencriptada = decrypt(mensajeEncriptado, private);
            println(palabraDesencriptada);
        }
        println("PARA SALIR PULSE 0, PARA CONTINUAR CUALQUIER OTRO NUMERO: ")
        var exit = readln().toIntOrNull() ?: 1

    } while (exit != 0)


}

fun menu(): Int {
    var option = 0;
    println("===============================")
    println("==============MENU=============")
    println("1. ENVIAR MENSAJE ENCRIPTADO")
    println("2. RECIBIR MENSAJE ENCRIPTADO")
    do {
        print("DIGITE LA OPCION: ")
        option = readln().toIntOrNull() ?: 0;
    } while (option != 1 && option != 2)
    println("===============================")

    return option;
}

fun AskForMessage(): String {
    print("Escriba el mensaje clave a enviar: ")
    var message = readln();
    return message
}

fun generateKeys(): Pair<String, String> {
    val keyGen = KeyPairGenerator.getInstance(ALGORITHM).apply {
        initialize(512)
    }

    // Key generation
    val keys = keyGen.genKeyPair()

    // Transformation to String (well encoded)
    val publicKeyString = Base64.getEncoder().encodeToString(keys.public.encoded)
    val privateKeyString = Base64.getEncoder().encodeToString(keys.private.encoded)

    return Pair(publicKeyString, privateKeyString)
}

fun encrypt(message: String, publicKey: String): String {
    // From a String, we obtain the Public Key
    val publicBytes = Base64.getDecoder().decode(publicKey)
    val decodedKey = KeyFactory.getInstance(ALGORITHM).generatePublic(X509EncodedKeySpec(publicBytes))

    // With the public, we encrypt the message
    val cipher = Cipher.getInstance(ALGORITHM).apply {
        init(Cipher.ENCRYPT_MODE, decodedKey)
    }
    val bytes = cipher.doFinal(message.encodeToByteArray())
    return String(Base64.getEncoder().encode(bytes))
}

fun decrypt(encryptedMessage: String, privateKey: String): String {
    // From a String, we obtain the Private Key
    val publicBytes = Base64.getDecoder().decode(privateKey)
    val decodedKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(PKCS8EncodedKeySpec(publicBytes))

    // Knowing the Private Key, we can decrypt the message
    val cipher = Cipher.getInstance(ALGORITHM).apply {
        init(Cipher.DECRYPT_MODE, decodedKey)
    }
    val bytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage))
    return String(bytes)
}


