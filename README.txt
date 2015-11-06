Afin d'intérroger le serveur ZAP distant pour lancer les scans il faut s'assurer que :

1-Xvfb est bien installé sur le serveur (https://en.wikipedia.org/wiki/Xvfb)
2-Lancer ce dernier de cette façon : Xvfb :0.0 &
3-exporter la variable DISPLAy ==> export DISPLAY=:0.0
4-Lancer zap.sh sans la commande "-daemon" ==> sh zap.sh

######### BUGS DANS ZAP ############

1-Lors de la phase du spidering d'un site cible evitez de chcher la case "robots.txt" et "sitemap.xml" :
	-On implémentant l'authentification sur un site le cookie de sessions ne sont pas transmis au spider et donc il consulte le contenu des fichier "robots.txt" et "sitemap.xml" en utilisant des nouveaux cookies ce qui déconnecte l'utilisateur et invalide sa session.
	-Un ticket a été ouvert auprès de MOZILLA pour corriger ce problème




############ AJAX SPIDER ##############

le mode ForcedUser doit être activé et configuré: voir (https://groups.google.com/forum/#!topic/zaproxy-users/GRtzMJ4WJzk)

les alertes obtenues lors de l'ajax spidering ne remonte pas en mode "daemon" voir : https://github.com/zaproxy/zaproxy/issues/1792 