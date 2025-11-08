// BackDevConnect/src/middleware/auth.js
// Middleware para autenticación y autorización

const { supabase } = require('../lib/supabase');

/**
 * Middleware para verificar autenticación
 * Verifica que el usuario esté autenticado y agrega la información del usuario a req.user
 */
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

        if (!token) {
            return res.status(401).json({
                success: false,
                error: 'Token de acceso requerido'
            });
        }

        // Verificar token con Supabase
        const { data: { user }, error } = await supabase.auth.getUser(token);

        if (error || !user) {
            return res.status(401).json({
                success: false,
                error: 'Token inválido o expirado'
            });
        }

        // 🆕 Obtener el perfil completo con el role
        const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('id, full_name, username, avatar_url, role')
            .eq('id', user.id)
            .single();

        // Agregar información del usuario a la request
        req.user = {
            id: user.id,
            email: user.email,
            role: profile?.role || 'user', // 🆕 Incluir el role
            ...user.user_metadata
        };

        next();
    } catch (error) {
        console.error('Error en middleware de autenticación:', error);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor'
        });
    }
};

/**
 * Middleware opcional para autenticación
 * No falla si no hay token, pero agrega la información del usuario si existe
 */
const optionalAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];

        if (token) {
            const { data: { user }, error } = await supabase.auth.getUser(token);
            
            if (!error && user) {
                // Obtener el perfil con role
                const { data: profile } = await supabase
                    .from('profiles')
                    .select('role')
                    .eq('id', user.id)
                    .single();

                req.user = {
                    id: user.id,
                    email: user.email,
                    role: profile?.role || 'user',
                    ...user.user_metadata
                };
            }
        }

        next();
    } catch (error) {
        console.error('Error en middleware opcional de autenticación:', error);
        next();
    }
};

/**
 * Middleware para verificar roles de usuario
 * @param {string[]} allowedRoles - Roles permitidos
 */
const requireRole = (allowedRoles) => {
    return (req, res, next) => {
        try {
            const userRole = req.user?.role || 'user';

            if (!allowedRoles.includes(userRole)) {
                return res.status(403).json({
                    success: false,
                    error: 'No tienes permisos suficientes para realizar esta acción'
                });
            }

            next();
        } catch (error) {
            console.error('Error en middleware de roles:', error);
            res.status(500).json({
                success: false,
                error: 'Error interno del servidor'
            });
        }
    };
};

/**
 * Middleware para verificar que el usuario sea el propietario del recurso
 * Debe usarse después de authenticateToken
 */
const requireOwnership = (resourceType) => {
    return async (req, res, next) => {
        try {
            const userId = req.user?.id;
            const resourceId = req.params.id;

            if (!userId) {
                return res.status(401).json({
                    success: false,
                    error: 'Usuario no autenticado'
                });
            }

            // Si es admin, permitir acceso
            if (req.user.role === 'admin') {
                return next();
            }

            // Verificar propiedad del recurso
            let query;
            switch (resourceType) {
                case 'project':
                    query = supabase
                        .from('projects')
                        .select('user_id')
                        .eq('id', resourceId)
                        .single();
                    break;
                case 'profile':
                    query = supabase
                        .from('profiles')
                        .select('id')
                        .eq('id', resourceId)
                        .single();
                    break;
                default:
                    return res.status(500).json({
                        success: false,
                        error: 'Tipo de recurso no válido'
                    });
            }

            const { data, error } = await query;

            if (error) {
                if (error.code === 'PGRST116') {
                    return res.status(404).json({
                        success: false,
                        error: `${resourceType} no encontrado`
                    });
                }
                throw error;
            }

            // Verificar que el usuario sea el propietario
            const ownerId = resourceType === 'project' ? data.user_id : data.id;
            if (ownerId !== userId) {
                return res.status(403).json({
                    success: false,
                    error: 'No tienes permisos para realizar esta acción'
                });
            }

            next();
        } catch (error) {
            console.error('Error en middleware de propiedad:', error);
            res.status(500).json({
                success: false,
                error: 'Error interno del servidor'
            });
        }
    };
};

module.exports = {
    authenticateToken,
    optionalAuth,
    requireOwnership,
    requireRole
};