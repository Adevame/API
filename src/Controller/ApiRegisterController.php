<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class ApiRegisterController extends AbstractController
{

    private JWTTokenManagerInterface $jwtManager;
    private EntityManagerInterface $em;
    private UserPasswordHasherInterface $userPasswordHasher;

    public function __construct(JWTTokenManagerInterface $jwtManager, EntityManagerInterface $em, UserPasswordHasherInterface $userPasswordHasher)
    {
        $this->jwtManager = $jwtManager;
        $this->em = $em;
        $this->userPasswordHasher = $userPasswordHasher;
    }

    #[Route('/api/register', name: 'app_api_register')]
    public function register(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        if (!isset($data['username']) || !isset($data['password'])) {
            return $this->json(['error' => 'Missing username or password'], Response::HTTP_BAD_REQUEST);
        }

        $user = new User();
        $user->setEmail($data['username']);

        $hashedPassword = $this->userPasswordHasher->hashPassword($user, $data['password']);
        $user->setPassword($hashedPassword);

        $user->setRoles(["ROLE_USER"]);

        $this->em->persist($user);
        $this->em->flush();

        $token = $this->jwtManager->create($user);

        return new JsonResponse([
            'roles' => "ROLE_USER",
            'token' => $token,
        ], Response::HTTP_CREATED);
    }
}
