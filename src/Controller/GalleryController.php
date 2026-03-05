<?php

namespace App\Controller;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Filesystem\Path;
use Symfony\Component\Finder\Finder;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\File\Exception\FileNotFoundException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * Controller used to manage private image gallery access.
 * Images are stored outside the public folder for security.
 *
 * @author Antoine <antoine.bourget@atos.net>
 */
#[Route('/gallery')]
#[IsGranted(User::ROLE_USER)]
final class GalleryController extends AbstractController
{
    /**
     * Display the gallery page with list of available images.
     */
    #[Route('/', name: 'gallery_index', methods: ['GET'])]
    public function index(
        #[Autowire('%app.private_uploads_dir%')] string $uploadsDir,
        #[Autowire('%app.private_uploads_extensions%')] array $allowedExtensions,
    ): Response {
        $images = [];

        if (is_dir($uploadsDir)) {
            $finder = new Finder();
            $finder->files()
                ->in($uploadsDir)
                ->name('/\.(' . implode('|', $allowedExtensions) . ')$/i')
                ->sortByModifiedTime()
                ->reverseSorting(); // Most recent first

            foreach ($finder as $file) {
                $images[] = [
                    'filename' => $file->getFilename(),
                    'size' => $file->getSize(),
                    'mtime' => $file->getMTime(),
                ];
            }
        }

        return $this->render('gallery/index.html.twig', [
            'images' => $images,
        ]);
    }

    /**
     * Stream an image file with security validation.
     * Validates filename to prevent directory traversal attacks.
     */
    #[Route('/image/{filename}', name: 'gallery_stream', methods: ['GET'])]
    public function imageStream(
        string $filename,
        #[Autowire('%app.private_uploads_dir%')] string $uploadsDir,
        #[Autowire('%app.private_uploads_extensions%')] array $allowedExtensions,
    ): BinaryFileResponse {
        // Validate filename format (prevent directory traversal)
        if (str_contains($filename, '..') || str_contains($filename, '/') || str_contains($filename, '\\')) {
            throw new AccessDeniedHttpException('Invalid filename.');
        }

        // Construct absolute path using Symfony Path component
        $filePath = Path::join($uploadsDir, $filename);

        // Validate that the file is within the uploads directory using Path::isBasePath
        if (!Path::isBasePath($uploadsDir, $filePath)) {
            throw new AccessDeniedHttpException('Access to this file is denied.');
        }

        // Check if file exists
        if (!file_exists($filePath) || !is_file($filePath)) {
            throw new FileNotFoundException($filePath);
        }

        // Validate extension
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if (!in_array($extension, $allowedExtensions, true)) {
            throw new AccessDeniedHttpException('Invalid file type.');
        }

        // Return the file with inline display (not download)
        return $this->file($filePath, $filename, ResponseHeaderBag::DISPOSITION_INLINE);
    }
}
