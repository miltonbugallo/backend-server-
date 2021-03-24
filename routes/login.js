var express = require('express');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');

var SEED = require('../config/config').SEED;

var app = express();
var Usuario = require('../models/usuario');



const GOOGLE_CLIENT_ID = require('../config/config').GOOGLE_CLIENT_ID;

// ==========================================
//  Autenticación De Google
// ==========================================

const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(GOOGLE_CLIENT_ID);
async function verify(token) {
    const ticket = await client.verifyIdToken({
        idToken: token,
        audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const userid = payload['sub'];

    return {
        nombre: payload.name,
        email: payload.email,
        img: payload.picture,
        google: true
    }

}

app.post('/google', async(req, res) => {

    var token = req.body.token;

    var googleUser = await verify(token).catch(e => {
        return res.status(403).json({
            ok: false,
            mensaje: 'Token no válido',
            errors: e
        });
    })

    Usuario.findOne({ email: googleUser.email }, (err, usuario) => {

        if (err) {
            return res.status(500).json({
                ok: true,
                mensaje: 'Error al buscar usuario - login',
                errors: err
            });
        }
        if (usuario) {

            if (usuario.google === false) {
                return res.status(400).json({
                    ok: true,
                    mensaje: 'Debe de usar su autenticación normal'
                });
            } else {

                usuario.password = ':)';

                var token = jwt.sign({ usuario: usuario }, SEED, { expiresIn: 14400 }); // 4 horas

                res.status(200).json({
                    ok: true,
                    usuario: usuario,
                    token: token,
                    id: usuario._id
                });

            }
            // Si el usuario no existe por correo
        } else {

            var usuario = new Usuario();
            usuario.nombre = googleUser.nombre;
            usuario.email = googleUser.email;
            usuario.password = ':)';
            usuario.img = googleUser.img;
            usuario.google = true;

            usuario.save((err, usuarioDB) => {

                if (err) {
                    return res.status(500).json({
                        ok: true,
                        mensaje: 'Error al crear usuario - google',
                        errors: err
                    });
                }

                var token = jwt.sign({ usuario: usuarioDB }, SEED, { expiresIn: 14400 }); // 4 horas

                res.status(200).json({
                    ok: true,
                    usuario: usuarioDB,
                    token: token,
                    id: usuarioDB._id
                });
            });
        }
    });
});

// ==========================================
//  Autenticación normal
// ==========================================
app.post('/', (req, res) => {

    var body = req.body;

    Usuario.findOne({ email: body.email }, (err, usuarioDB) => {

        if (err) {
            return res.status(500).json({
                ok: false,
                mensaje: 'Error al buscar usuario',
                errors: err
            });
        }

        if (!usuarioDB) {
            return res.status(400).json({
                ok: false,
                mensaje: 'Credenciales incorrectas - email',
                errors: err
            });
        }

        if (!bcrypt.compareSync(body.password, usuarioDB.password)) {
            return res.status(400).json({
                ok: false,
                mensaje: 'Credenciales incorrectas - password',
                errors: err
            });
        }

        // Crear un token!!!
        usuarioDB.password = ':)';

        var token = jwt.sign({ usuario: usuarioDB }, SEED, { expiresIn: 14400 }); // 4 horas

        res.status(200).json({
            ok: true,
            usuario: usuarioDB,
            token: token,
            id: usuarioDB._id
        });

    })


});





module.exports = app;