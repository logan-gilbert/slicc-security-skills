import unittest
from scripts.analyze_citation_image import analyze_image, extract_citation_info

class TestAnalyzeCitationImage(unittest.TestCase):

    def test_analyze_image_valid(self):
        result = analyze_image('path/to/valid/image.png')
        self.assertIsNotNone(result)
        self.assertIn('citation', result)

    def test_analyze_image_invalid(self):
        result = analyze_image('path/to/invalid/image.png')
        self.assertIsNone(result)

    def test_extract_citation_info(self):
        citation_data = {'text': 'Sample citation text', 'format': 'APA'}
        result = extract_citation_info(citation_data)
        self.assertEqual(result['format'], 'APA')
        self.assertIn('citation', result)

if __name__ == '__main__':
    unittest.main()